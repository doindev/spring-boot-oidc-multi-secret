package com.example.oidc.config;

import com.example.oidc.filter.CorrelationIdFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

/**
 * No security configuration - all endpoints are open.
 * This is used when security.type=none
 */
@Configuration
@EnableWebSecurity
@ConditionalOnProperty(name = "security.type", havingValue = "none")
public class NoSecurityConfig {
    
    private final CorrelationIdFilter correlationIdFilter;
    
    public NoSecurityConfig(CorrelationIdFilter correlationIdFilter) {
        this.correlationIdFilter = correlationIdFilter;
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Add correlation ID filter at the very beginning
            .addFilterBefore(correlationIdFilter, WebAsyncManagerIntegrationFilter.class)
            
            // Disable security
            .authorizeHttpRequests(authz -> authz
                .anyRequest().permitAll()
            )
            
            // Disable CSRF for simplicity when security is off
            .csrf(csrf -> csrf.disable());
        
        return http.build();
    }
}