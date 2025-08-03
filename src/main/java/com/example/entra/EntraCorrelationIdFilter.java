package com.example.entra;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Filter to handle correlation and transaction IDs for request tracking in Entra setup.
 * Specific to Entra configuration to avoid sharing with OIDC setup.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@ConditionalOnProperty(name = "security.type", havingValue = "entra")
public class EntraCorrelationIdFilter extends OncePerRequestFilter {
    
    private static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    private static final String TRANSACTION_ID_HEADER = "X-Transaction-Id";
    private static final String CORRELATION_ID_MDC_KEY = "correlationId";
    private static final String TRANSACTION_ID_MDC_KEY = "transactionId";
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        // Extract or generate correlation ID
        String correlationId = extractCorrelationId(request);
        String transactionId = generateTransactionId();
        
        // Set in MDC for logging
        MDC.put(CORRELATION_ID_MDC_KEY, correlationId);
        MDC.put(TRANSACTION_ID_MDC_KEY, transactionId);
        
        // Set in request attributes
        request.setAttribute(CORRELATION_ID_MDC_KEY, correlationId);
        request.setAttribute(TRANSACTION_ID_MDC_KEY, transactionId);
        
        // Set in ThreadLocal for access throughout the request
        EntraTransactionContext.setCorrelationId(correlationId);
        EntraTransactionContext.setTransactionId(transactionId);
        
        log.debug("Processing request with correlationId: {} and transactionId: {}", correlationId, transactionId);
        
        try {
            // Add headers to response
            response.setHeader(CORRELATION_ID_HEADER, correlationId);
            response.setHeader(TRANSACTION_ID_HEADER, transactionId);
            
            filterChain.doFilter(request, response);
        } finally {
            // Clean up
            MDC.remove(CORRELATION_ID_MDC_KEY);
            MDC.remove(TRANSACTION_ID_MDC_KEY);
            EntraTransactionContext.clear();
        }
    }
    
    private String extractCorrelationId(HttpServletRequest request) {
        // Check various headers for correlation ID
        String correlationId = request.getHeader(CORRELATION_ID_HEADER);
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = request.getHeader("X-Request-Id");
        }
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = request.getHeader("X-Trace-Id");
        }
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = request.getHeader("X-B3-TraceId");
        }
        
        // Generate new if not found
        if (correlationId == null || correlationId.isEmpty()) {
            correlationId = "entra-" + UUID.randomUUID().toString();
            log.debug("No correlation ID found in request headers, generated new: {}", correlationId);
        }
        
        return correlationId;
    }
    
    private String generateTransactionId() {
        return "txn-" + UUID.randomUUID().toString();
    }
}