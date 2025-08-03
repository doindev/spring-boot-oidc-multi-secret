package com.example.entra;

/**
 * ThreadLocal context for storing transaction and correlation IDs.
 * Specific to Entra configuration.
 */
public class EntraTransactionContext {
    
    private static final ThreadLocal<String> correlationIdHolder = new ThreadLocal<>();
    private static final ThreadLocal<String> transactionIdHolder = new ThreadLocal<>();
    
    public static void setCorrelationId(String correlationId) {
        correlationIdHolder.set(correlationId);
    }
    
    public static String getCorrelationId() {
        return correlationIdHolder.get();
    }
    
    public static void setTransactionId(String transactionId) {
        transactionIdHolder.set(transactionId);
    }
    
    public static String getTransactionId() {
        return transactionIdHolder.get();
    }
    
    public static void clear() {
        correlationIdHolder.remove();
        transactionIdHolder.remove();
    }
}