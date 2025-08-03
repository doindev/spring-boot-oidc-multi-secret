package com.example.oidc.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@ExtendWith(MockitoExtension.class)
class ClientRegistrationRepositoryWithMultiSecretSupportTest {
    
    @Mock
    private ClientRegistrationWithMultiSecretSupport multiSecretClientRegistration;
    
    @Mock
    private OidcProperties oidcProperties;
    
    private ClientRegistrationRepositoryWithMultiSecretSupport repository;
    
    @BeforeEach
    void setUp() {
        repository = new ClientRegistrationRepositoryWithMultiSecretSupport(multiSecretClientRegistration, oidcProperties);
    }
    
    @Test
    void testFindByRegistrationId() {
        ClientRegistration mockRegistration = ClientRegistration.withRegistrationId("test")
            .clientId("test-client")
            .clientSecret("test-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:8080/callback")
            .authorizationUri("https://test.com/auth")
            .tokenUri("https://test.com/token")
            .build();
            
        when(multiSecretClientRegistration.getCurrentClientRegistration()).thenReturn(mockRegistration);
        
        ClientRegistration result = repository.findByRegistrationId("any-id");
        
        assertNotNull(result);
        assertEquals("test", result.getRegistrationId());
        assertEquals("test-client", result.getClientId());
        verify(multiSecretClientRegistration).getCurrentClientRegistration();
    }
    
    @Test
    void testInit_SingleSecret_NoPolling() {
        when(multiSecretClientRegistration.getTotalSecrets()).thenReturn(1);
        
        repository.init();
        
        // With single secret, no polling should be started
        verify(multiSecretClientRegistration).getTotalSecrets();
        verifyNoMoreInteractions(oidcProperties);
    }
    
    @Test
    void testInit_MultipleSecrets_StartsPolling() {
        when(multiSecretClientRegistration.getTotalSecrets()).thenReturn(3);
        when(oidcProperties.getSecretRotationIntervalMs()).thenReturn(60000L);
        
        repository.init();
        
        verify(multiSecretClientRegistration, times(2)).getTotalSecrets();
        verify(oidcProperties).getSecretRotationIntervalMs();
    }
    
    @Test
    void testDestroy() {
        // Test that destroy method handles null scheduler gracefully
        assertDoesNotThrow(() -> repository.destroy());
        
        // Test with initialized scheduler
        when(multiSecretClientRegistration.getTotalSecrets()).thenReturn(2);
        when(oidcProperties.getSecretRotationIntervalMs()).thenReturn(60000L);
        
        repository.init();
        assertDoesNotThrow(() -> repository.destroy());
    }
}