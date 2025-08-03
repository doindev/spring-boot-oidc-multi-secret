package com.example.oidc.config;

import com.example.oidc.filter.CorrelationIdFilter;
import com.example.oidc.filter.TransactionContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.time.Duration;

/**
 * Configuration for RestTemplate with correlation ID propagation.
 */
@Configuration
@Slf4j
public class RestTemplateConfig {
    
    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {
        return builder
            .setConnectTimeout(Duration.ofSeconds(5))
            .setReadTimeout(Duration.ofSeconds(30))
            .interceptors(new CorrelationIdInterceptor())
            .build();
    }
    
    /**
     * Interceptor to propagate correlation ID to downstream services.
     * This ensures distributed tracing across microservices.
     */
    @Slf4j
    static class CorrelationIdInterceptor implements ClientHttpRequestInterceptor {
        
        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, 
                                          ClientHttpRequestExecution execution) throws IOException {
            
            // Get correlation ID from thread context
            String correlationId = TransactionContext.getCorrelationId();
            
            // Add correlation ID to outgoing request if available
            if (StringUtils.hasText(correlationId)) {
                request.getHeaders().set(CorrelationIdFilter.CORRELATION_ID_HEADER, correlationId);
                log.debug("Added correlation ID to outgoing request: {} to {}", 
                         correlationId, request.getURI());
            }
            
            // Note: We don't propagate transaction ID as it's unique to each request/response cycle
            
            return execution.execute(request, body);
        }
    }
}