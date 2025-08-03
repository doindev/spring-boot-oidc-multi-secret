# Correlation and Transaction ID Tracking

This application implements automatic correlation and transaction ID tracking for all REST API calls to enable distributed tracing and request tracking.

## Overview

- **Correlation ID**: A unique identifier that follows a request across multiple services/systems. If a client provides one, it's used; otherwise, a new one is generated.
- **Transaction ID**: A unique identifier generated for each individual request/response cycle. Always generated new for each request.

## How It Works

1. **CorrelationIdFilter** runs very early in the filter chain (before Spring Security)
2. It checks for correlation ID in request headers (supports multiple header names)
3. Always generates a new transaction ID
4. Stores IDs in:
   - Request attributes
   - MDC for logging
   - ThreadLocal for easy access
   - Response headers

## Request Headers

The filter checks for correlation ID in these headers (in order):
- `X-Correlation-Id` (primary)
- `X-Request-Id` (alternative)
- `X-Trace-Id` (alternative)

## Response Headers

Every response includes:
- `X-Correlation-Id`: The correlation ID used for this request
- `X-Transaction-Id`: The unique transaction ID for this request

## Usage Examples

### 1. Client Sending Correlation ID

```bash
curl -H "X-Correlation-Id: client-corr-12345" http://localhost:8080/api/health

# Response headers will include:
# X-Correlation-Id: client-corr-12345
# X-Transaction-Id: txn-<generated-id>
```

### 2. Automatic Generation

```bash
curl http://localhost:8080/api/health

# Response headers will include:
# X-Correlation-Id: corr-<generated-id>
# X-Transaction-Id: txn-<generated-id>
```

### 3. Accessing IDs in Code

```java
// In a controller or service
import com.example.oidc.util.RequestTrackingUtil;

@RestController
public class MyController {
    
    @GetMapping("/api/example")
    public ResponseEntity<Map<String, String>> example() {
        // Get IDs
        String correlationId = RequestTrackingUtil.getCorrelationId();
        String transactionId = RequestTrackingUtil.getTransactionId();
        
        // Log with IDs (automatically included via MDC)
        log.info("Processing example request");
        
        // Or manually include in log
        log.info("{}Processing with custom message", 
                RequestTrackingUtil.getLogPrefix());
        
        return ResponseEntity.ok(Map.of(
            "correlationId", correlationId,
            "transactionId", transactionId
        ));
    }
}
```

### 4. RestTemplate Integration

When making outbound REST calls, the correlation ID is automatically propagated:

```java
@Autowired
private RestTemplate restTemplate; // Configured with correlation interceptor

// The correlation ID will be automatically added to outgoing requests
ResponseEntity<String> response = restTemplate.getForEntity(
    "http://another-service/api/endpoint", 
    String.class
);
```

## Log Format

All logs now include correlation and transaction IDs:

```
2025-08-03 17:07:15 - Processing request with correlationId: corr-123 and transactionId: txn-456 [main] [correlationId=corr-123] [transactionId=txn-456] c.e.oidc.filter.CorrelationIdFilter - 
```

## Best Practices

1. **Always propagate correlation IDs** to downstream services
2. **Log correlation IDs** in error messages for easier debugging
3. **Include IDs in error responses** to help with support tickets
4. **Use correlation IDs in monitoring** to trace requests across services
5. **Never modify transaction IDs** - they're unique per request

## Configuration

The logging pattern is configured in `application.yml`:

```yaml
logging:
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg [%thread] [correlationId=%X{correlationId:-N/A}] [transactionId=%X{transactionId:-N/A}] %logger{36} - %n"
```

## Security Considerations

- IDs are generated using secure random UUIDs
- No sensitive information is included in the IDs
- IDs are cleared from ThreadLocal after each request to prevent leaks