package com.example.oidc.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Filter to handle correlation ID and transaction ID for request tracking.
 * This filter should run very early in the filter chain to ensure IDs are available
 * for all subsequent processing.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {
    
    // Standard header names for correlation tracking
    public static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    public static final String TRANSACTION_ID_HEADER = "X-Transaction-Id";
    
    // Alternative header names that might be used by clients
    public static final String ALT_CORRELATION_ID_HEADER = "X-Request-Id";
    public static final String ALT_TRACE_ID_HEADER = "X-Trace-Id";
    
    // Request attribute names for storing IDs
    public static final String CORRELATION_ID_ATTR = "correlationId";
    public static final String TRANSACTION_ID_ATTR = "transactionId";
    
    // MDC keys for logging
    public static final String MDC_CORRELATION_ID = "correlationId";
    public static final String MDC_TRANSACTION_ID = "transactionId";
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        try {
            // Extract or generate correlation ID
            String correlationId = extractCorrelationId(request);
            
            // Always generate a new transaction ID for this specific request/response cycle
            String transactionId = generateTransactionId();
            
            // Store in request attributes for application access
            request.setAttribute(CORRELATION_ID_ATTR, correlationId);
            request.setAttribute(TRANSACTION_ID_ATTR, transactionId);
            
            // Store in MDC for logging
            MDC.put(MDC_CORRELATION_ID, correlationId);
            MDC.put(MDC_TRANSACTION_ID, transactionId);
            
            // Store in TransactionContext for thread-local access
            TransactionContext.setCorrelationId(correlationId);
            TransactionContext.setTransactionId(transactionId);
            
            // Add headers to response
            response.setHeader(CORRELATION_ID_HEADER, correlationId);
            response.setHeader(TRANSACTION_ID_HEADER, transactionId);
            
            log.debug("Processing request with correlationId: {} and transactionId: {}", 
                     correlationId, transactionId);
            
            // Continue with the filter chain
            filterChain.doFilter(request, response);
            
        } finally {
            // Clean up MDC and ThreadLocal to prevent memory leaks
            MDC.remove(MDC_CORRELATION_ID);
            MDC.remove(MDC_TRANSACTION_ID);
            TransactionContext.clear();
        }
    }
    
    /**
     * Extract correlation ID from request headers or generate a new one.
     * Checks multiple possible header names for compatibility.
     */
    private String extractCorrelationId(HttpServletRequest request) {
        // Check primary header
        String correlationId = request.getHeader(CORRELATION_ID_HEADER);
        
        // Check alternative headers if primary is not found
        if (!StringUtils.hasText(correlationId)) {
            correlationId = request.getHeader(ALT_CORRELATION_ID_HEADER);
        }
        
        if (!StringUtils.hasText(correlationId)) {
            correlationId = request.getHeader(ALT_TRACE_ID_HEADER);
        }
        
        // Generate new ID if none found
        if (!StringUtils.hasText(correlationId)) {
            correlationId = generateCorrelationId();
            log.debug("No correlation ID found in request headers, generated new: {}", correlationId);
        } else {
            log.debug("Using correlation ID from request header: {}", correlationId);
        }
        
        return correlationId;
    }
    
    /**
     * Generate a new correlation ID.
     * Format: "corr-" + UUID (without hyphens for compactness)
     */
    private String generateCorrelationId() {
        return "corr-" + UUID.randomUUID().toString().replace("-", "");
    }
    
    /**
     * Generate a new transaction ID.
     * Format: "txn-" + UUID (without hyphens for compactness)
     */
    private String generateTransactionId() {
        return "txn-" + UUID.randomUUID().toString().replace("-", "");
    }
}