package com.example.oidc.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Configuration for OAuth2 client components including token refresh support.
 */
@Configuration
@ConditionalOnProperty(name = "security.type", havingValue = "oidc")
public class OAuth2ClientConfig {
    
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
        
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken(refreshToken -> 
                            refreshToken.clockSkew(Duration.ofSeconds(60)))
                        .clientCredentials()
                        .build();
        
        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);
        
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        
        // Configure success/failure handlers
        authorizedClientManager.setAuthorizationSuccessHandler((authorizedClient, principal, attributes) -> {
            // Log successful token refresh
            if (authorizedClient.getRefreshToken() != null) {
                System.out.println("Successfully refreshed token for principal: " + principal.getName());
            }
        });
        
        authorizedClientManager.setAuthorizationFailureHandler((authorizationException, principal, attributes) -> {
            // Log token refresh failure
            System.err.println("Failed to refresh token for principal: " + 
                (principal != null ? principal.getName() : "unknown") + 
                ", error: " + authorizationException.getMessage());
        });
        
        // Configure context attribute mapper for refresh token grant
        authorizedClientManager.setContextAttributesMapper(authorizeRequest -> {
            // You can add custom attributes here if needed
            return authorizeRequest.getAttributes();
        });
        
        return authorizedClientManager;
    }
    
    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(
            ClientRegistrationRepository clientRegistrationRepository) {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
    }
}