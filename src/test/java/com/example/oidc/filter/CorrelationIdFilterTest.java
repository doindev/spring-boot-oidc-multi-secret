package com.example.oidc.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CorrelationIdFilterTest {
    
    private CorrelationIdFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain filterChain;
    
    @BeforeEach
    void setUp() {
        filter = new CorrelationIdFilter();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = mock(FilterChain.class);
        
        // Clear MDC and ThreadLocal before each test
        MDC.clear();
        TransactionContext.clear();
    }
    
    @Test
    void testFilter_GeneratesNewIds_WhenNoCorrelationIdProvided() throws ServletException, IOException {
        // When
        filter.doFilterInternal(request, response, filterChain);
        
        // Then
        // Verify IDs were set in request attributes
        String correlationId = (String) request.getAttribute(CorrelationIdFilter.CORRELATION_ID_ATTR);
        String transactionId = (String) request.getAttribute(CorrelationIdFilter.TRANSACTION_ID_ATTR);
        
        assertNotNull(correlationId);
        assertNotNull(transactionId);
        assertTrue(correlationId.startsWith("corr-"));
        assertTrue(transactionId.startsWith("txn-"));
        
        // Verify IDs were set in response headers
        assertEquals(correlationId, response.getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER));
        assertEquals(transactionId, response.getHeader(CorrelationIdFilter.TRANSACTION_ID_HEADER));
        
        // Verify filter chain was called
        verify(filterChain).doFilter(request, response);
    }
    
    @Test
    void testFilter_UsesProvidedCorrelationId() throws ServletException, IOException {
        // Given
        String providedCorrelationId = "test-correlation-id-123";
        request.addHeader(CorrelationIdFilter.CORRELATION_ID_HEADER, providedCorrelationId);
        
        // When
        filter.doFilterInternal(request, response, filterChain);
        
        // Then
        String correlationId = (String) request.getAttribute(CorrelationIdFilter.CORRELATION_ID_ATTR);
        assertEquals(providedCorrelationId, correlationId);
        assertEquals(providedCorrelationId, response.getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER));
    }
    
    @Test
    void testFilter_UsesAlternativeCorrelationIdHeaders() throws ServletException, IOException {
        // Test X-Request-Id header
        String requestId = "request-id-456";
        request.addHeader(CorrelationIdFilter.ALT_CORRELATION_ID_HEADER, requestId);
        
        filter.doFilterInternal(request, response, filterChain);
        
        String correlationId = (String) request.getAttribute(CorrelationIdFilter.CORRELATION_ID_ATTR);
        assertEquals(requestId, correlationId);
        
        // Reset for next test
        setUp();
        
        // Test X-Trace-Id header
        String traceId = "trace-id-789";
        request.addHeader(CorrelationIdFilter.ALT_TRACE_ID_HEADER, traceId);
        
        filter.doFilterInternal(request, response, filterChain);
        
        correlationId = (String) request.getAttribute(CorrelationIdFilter.CORRELATION_ID_ATTR);
        assertEquals(traceId, correlationId);
    }
    
    @Test
    void testFilter_AlwaysGeneratesNewTransactionId() throws ServletException, IOException {
        // Given
        request.addHeader(CorrelationIdFilter.TRANSACTION_ID_HEADER, "should-be-ignored");
        
        // When
        filter.doFilterInternal(request, response, filterChain);
        
        // Then
        String transactionId = (String) request.getAttribute(CorrelationIdFilter.TRANSACTION_ID_ATTR);
        assertNotNull(transactionId);
        assertTrue(transactionId.startsWith("txn-"));
        assertNotEquals("should-be-ignored", transactionId);
    }
    
    @Test
    void testFilter_SetsMDCValues() throws ServletException, IOException {
        // Create a custom filter chain to verify MDC values during request processing
        FilterChain customChain = (req, res) -> {
            // Verify MDC values are set during request processing
            assertNotNull(MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID));
            assertNotNull(MDC.get(CorrelationIdFilter.MDC_TRANSACTION_ID));
        };
        
        // When
        filter.doFilterInternal(request, response, customChain);
        
        // Then - MDC should be cleared after request
        assertNull(MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID));
        assertNull(MDC.get(CorrelationIdFilter.MDC_TRANSACTION_ID));
    }
    
    @Test
    void testFilter_SetsThreadLocalValues() throws ServletException, IOException {
        // Create a custom filter chain to verify ThreadLocal values during request processing
        FilterChain customChain = (req, res) -> {
            // Verify ThreadLocal values are set during request processing
            assertNotNull(TransactionContext.getCorrelationId());
            assertNotNull(TransactionContext.getTransactionId());
            
            String correlationId = (String) req.getAttribute(CorrelationIdFilter.CORRELATION_ID_ATTR);
            String transactionId = (String) req.getAttribute(CorrelationIdFilter.TRANSACTION_ID_ATTR);
            
            assertEquals(correlationId, TransactionContext.getCorrelationId());
            assertEquals(transactionId, TransactionContext.getTransactionId());
        };
        
        // When
        filter.doFilterInternal(request, response, customChain);
        
        // Then - ThreadLocal should be cleared after request
        assertNull(TransactionContext.getCorrelationId());
        assertNull(TransactionContext.getTransactionId());
    }
    
    @Test
    void testFilter_CleansUpOnException() throws ServletException, IOException {
        // Given
        FilterChain failingChain = mock(FilterChain.class);
        doThrow(new RuntimeException("Test exception")).when(failingChain).doFilter(any(), any());
        
        // When/Then
        assertThrows(RuntimeException.class, () -> 
            filter.doFilterInternal(request, response, failingChain)
        );
        
        // Verify cleanup happened
        assertNull(MDC.get(CorrelationIdFilter.MDC_CORRELATION_ID));
        assertNull(MDC.get(CorrelationIdFilter.MDC_TRANSACTION_ID));
        assertNull(TransactionContext.getCorrelationId());
        assertNull(TransactionContext.getTransactionId());
    }
}