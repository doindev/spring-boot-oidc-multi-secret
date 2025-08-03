package com.example.oidc.filter;

import com.example.oidc.config.TestSecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestSecurityConfig.class)
class CorrelationIdIntegrationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void testCorrelationId_GeneratedWhenNotProvided() throws Exception {
        MvcResult result = mockMvc.perform(get("/"))
            .andExpect(status().isOk())
            .andExpect(header().exists(CorrelationIdFilter.CORRELATION_ID_HEADER))
            .andExpect(header().exists(CorrelationIdFilter.TRANSACTION_ID_HEADER))
            .andReturn();
        
        String correlationId = result.getResponse().getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER);
        String transactionId = result.getResponse().getHeader(CorrelationIdFilter.TRANSACTION_ID_HEADER);
        
        assertNotNull(correlationId);
        assertNotNull(transactionId);
        assertTrue(correlationId.startsWith("corr-"));
        assertTrue(transactionId.startsWith("txn-"));
    }
    
    @Test
    void testCorrelationId_ProvidedHeaderIsUsed() throws Exception {
        String providedCorrelationId = "test-corr-id-12345";
        
        MvcResult result = mockMvc.perform(get("/")
                .header(CorrelationIdFilter.CORRELATION_ID_HEADER, providedCorrelationId))
            .andExpect(status().isOk())
            .andExpect(header().string(CorrelationIdFilter.CORRELATION_ID_HEADER, providedCorrelationId))
            .andExpect(header().exists(CorrelationIdFilter.TRANSACTION_ID_HEADER))
            .andReturn();
        
        String transactionId = result.getResponse().getHeader(CorrelationIdFilter.TRANSACTION_ID_HEADER);
        
        assertNotNull(transactionId);
        assertTrue(transactionId.startsWith("txn-"));
        // Transaction ID should be different from correlation ID
        assertNotEquals(providedCorrelationId, transactionId);
    }
    
    @Test
    void testCorrelationId_AlternativeHeaders() throws Exception {
        // Test with X-Request-Id
        String requestId = "req-id-67890";
        
        MvcResult result = mockMvc.perform(get("/")
                .header(CorrelationIdFilter.ALT_CORRELATION_ID_HEADER, requestId))
            .andExpect(status().isOk())
            .andExpect(header().string(CorrelationIdFilter.CORRELATION_ID_HEADER, requestId))
            .andReturn();
        
        // Test with X-Trace-Id
        String traceId = "trace-id-11111";
        
        result = mockMvc.perform(get("/")
                .header(CorrelationIdFilter.ALT_TRACE_ID_HEADER, traceId))
            .andExpect(status().isOk())
            .andExpect(header().string(CorrelationIdFilter.CORRELATION_ID_HEADER, traceId))
            .andReturn();
    }
    
    @Test
    void testCorrelationId_WorksWithAuthenticatedEndpoints() throws Exception {
        String correlationId = "auth-corr-id-22222";
        
        // API endpoints should include correlation headers even when returning 401
        mockMvc.perform(get("/api/user")
                .header(CorrelationIdFilter.CORRELATION_ID_HEADER, correlationId))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string(CorrelationIdFilter.CORRELATION_ID_HEADER, correlationId))
            .andExpect(header().exists(CorrelationIdFilter.TRANSACTION_ID_HEADER));
    }
    
    @Test
    void testCorrelationId_DifferentTransactionIdPerRequest() throws Exception {
        String correlationId = "multi-req-corr-id-33333";
        
        // Make first request
        MvcResult result1 = mockMvc.perform(get("/")
                .header(CorrelationIdFilter.CORRELATION_ID_HEADER, correlationId))
            .andExpect(status().isOk())
            .andReturn();
        
        String transactionId1 = result1.getResponse().getHeader(CorrelationIdFilter.TRANSACTION_ID_HEADER);
        
        // Make second request with same correlation ID
        MvcResult result2 = mockMvc.perform(get("/")
                .header(CorrelationIdFilter.CORRELATION_ID_HEADER, correlationId))
            .andExpect(status().isOk())
            .andReturn();
        
        String transactionId2 = result2.getResponse().getHeader(CorrelationIdFilter.TRANSACTION_ID_HEADER);
        
        // Same correlation ID should be returned
        assertEquals(correlationId, result1.getResponse().getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER));
        assertEquals(correlationId, result2.getResponse().getHeader(CorrelationIdFilter.CORRELATION_ID_HEADER));
        
        // But transaction IDs should be different
        assertNotEquals(transactionId1, transactionId2);
    }
}