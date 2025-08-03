package com.example.oidc.util;

import com.example.oidc.filter.CorrelationIdFilter;
import com.example.oidc.filter.TransactionContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Utility class for accessing correlation and transaction IDs.
 * Provides multiple ways to retrieve the IDs based on the context.
 */
public class RequestTrackingUtil {
    
    private RequestTrackingUtil() {
        // Utility class, prevent instantiation
    }
    
    /**
     * Get correlation ID from the current request context.
     * First tries HttpServletRequest attributes, then falls back to ThreadLocal.
     */
    public static String getCorrelationId() {
        // Try to get from request attributes first
        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            Object correlationId = request.getAttribute(CorrelationIdFilter.CORRELATION_ID_ATTR);
            if (correlationId != null) {
                return correlationId.toString();
            }
        }
        
        // Fall back to ThreadLocal
        return TransactionContext.getCorrelationId();
    }
    
    /**
     * Get transaction ID from the current request context.
     * First tries HttpServletRequest attributes, then falls back to ThreadLocal.
     */
    public static String getTransactionId() {
        // Try to get from request attributes first
        HttpServletRequest request = getCurrentRequest();
        if (request != null) {
            Object transactionId = request.getAttribute(CorrelationIdFilter.TRANSACTION_ID_ATTR);
            if (transactionId != null) {
                return transactionId.toString();
            }
        }
        
        // Fall back to ThreadLocal
        return TransactionContext.getTransactionId();
    }
    
    /**
     * Get the current HttpServletRequest if available.
     */
    private static HttpServletRequest getCurrentRequest() {
        ServletRequestAttributes attributes = 
            (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        
        if (attributes != null) {
            return attributes.getRequest();
        }
        
        return null;
    }
    
    /**
     * Create a log message prefix with correlation and transaction IDs.
     */
    public static String getLogPrefix() {
        return String.format("[correlationId=%s, transactionId=%s] ", 
                           getCorrelationId(), getTransactionId());
    }
}