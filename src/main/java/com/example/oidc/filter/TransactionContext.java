package com.example.oidc.filter;

/**
 * Thread-local storage for transaction and correlation IDs.
 * Provides easy access to these IDs throughout the request processing lifecycle.
 */
public class TransactionContext {
    
    private static final ThreadLocal<String> correlationIdHolder = new ThreadLocal<>();
    private static final ThreadLocal<String> transactionIdHolder = new ThreadLocal<>();
    
    /**
     * Set the correlation ID for the current thread.
     */
    public static void setCorrelationId(String correlationId) {
        correlationIdHolder.set(correlationId);
    }
    
    /**
     * Get the correlation ID for the current thread.
     */
    public static String getCorrelationId() {
        return correlationIdHolder.get();
    }
    
    /**
     * Set the transaction ID for the current thread.
     */
    public static void setTransactionId(String transactionId) {
        transactionIdHolder.set(transactionId);
    }
    
    /**
     * Get the transaction ID for the current thread.
     */
    public static String getTransactionId() {
        return transactionIdHolder.get();
    }
    
    /**
     * Clear all context data for the current thread.
     * Important to call this to prevent memory leaks in thread pools.
     */
    public static void clear() {
        correlationIdHolder.remove();
        transactionIdHolder.remove();
    }
    
    /**
     * Get both IDs as a formatted string for logging.
     */
    public static String getContextString() {
        return String.format("[correlationId=%s, transactionId=%s]", 
                           getCorrelationId(), getTransactionId());
    }
}