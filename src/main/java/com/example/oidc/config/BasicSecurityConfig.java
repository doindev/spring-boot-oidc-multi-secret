package com.example.oidc.config;

import com.example.oidc.filter.CorrelationIdFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import jakarta.servlet.http.HttpServletResponse;

/**
 * Basic security configuration that uses in-memory authentication.
 * This is used when security.type=basic
 */
@Configuration
@EnableWebSecurity
@ConditionalOnProperty(name = "security.type", havingValue = "basic")
public class BasicSecurityConfig {
    
    private final CorrelationIdFilter correlationIdFilter;
    
    public BasicSecurityConfig(CorrelationIdFilter correlationIdFilter) {
        this.correlationIdFilter = correlationIdFilter;
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Add correlation ID filter at the very beginning
            .addFilterBefore(correlationIdFilter, WebAsyncManagerIntegrationFilter.class)
            
            // Basic authentication
            .httpBasic(basic -> basic.realmName("Basic Authentication"))
            
            // Authorization rules
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/error", "/health").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            
            // Exception handling
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    (request, response, authException) -> {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                    },
                    request -> request.getRequestURI().startsWith("/api/")
                )
            )
            
            // Session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionStrategy((request, response) -> {
                    if (request.getRequestURI().startsWith("/api/")) {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session expired");
                    } else {
                        response.sendRedirect("/");
                    }
                })
            );
        
        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build());
        manager.createUser(User.withDefaultPasswordEncoder()
            .username("admin")
            .password("admin")
            .roles("USER", "ADMIN")
            .build());
        return manager;
    }
}