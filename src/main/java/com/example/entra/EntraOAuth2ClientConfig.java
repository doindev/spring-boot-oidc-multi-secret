package com.example.entra;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * OAuth2 client configuration specific to Microsoft Entra ID.
 */
@Slf4j
@Configuration
@ConditionalOnProperty(name = "security.type", havingValue = "entra")
public class EntraOAuth2ClientConfig {
    
    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
        
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .clientCredentials()
                        .build();
        
        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        
        // Configure for Entra-specific token handling
        authorizedClientManager.setAuthorizationSuccessHandler((authorizedClient, principal, attributes) -> {
            log.debug("Entra authorization successful for principal: {}", principal.getName());
        });
        
        authorizedClientManager.setAuthorizationFailureHandler((authorizationException, principal, attributes) -> {
            log.error("Entra authorization failed for principal: {}", 
                principal != null ? principal.getName() : "anonymous", authorizationException);
        });
        
        return authorizedClientManager;
    }
}