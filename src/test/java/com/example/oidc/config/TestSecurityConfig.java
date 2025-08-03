package com.example.oidc.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;

@TestConfiguration
public class TestSecurityConfig {
    
    @Bean
    @Primary
    public OAuth2AuthorizedClientRepository testOAuth2AuthorizedClientRepository() {
        return new OAuth2AuthorizedClientRepository() {
            @Override
            public OAuth2AuthorizedClient loadAuthorizedClient(String clientRegistrationId, 
                    Authentication principal, HttpServletRequest request) {
                return null;
            }
            
            @Override
            public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, 
                    Authentication principal, HttpServletRequest request, HttpServletResponse response) {
            }
            
            @Override
            public void removeAuthorizedClient(String clientRegistrationId, 
                    Authentication principal, HttpServletRequest request, HttpServletResponse response) {
            }
        };
    }
}