package com.example.oidc.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class ClientRegistrationWithMultiSecretSupportTest {
    
    private OidcProperties oidcProperties;
    private ClientRegistrationWithMultiSecretSupport multiSecretClientRegistration;
    
    @BeforeEach
    void setUp() {
        oidcProperties = new OidcProperties();
        oidcProperties.setIssuerUri("https://test-issuer.com");
        oidcProperties.setClientId("test-client-id");
        oidcProperties.setClientSecrets(Arrays.asList("secret1", "secret2", "secret3"));
        oidcProperties.setRedirectUri("http://localhost:8080/callback");
        oidcProperties.setScopes(Arrays.asList("openid", "profile", "email"));
        oidcProperties.setAuthorizationUri("https://test-issuer.com/auth");
        oidcProperties.setTokenUri("https://test-issuer.com/token");
        oidcProperties.setUserInfoUri("https://test-issuer.com/userinfo");
        oidcProperties.setJwkSetUri("https://test-issuer.com/jwks");
        
        multiSecretClientRegistration = new ClientRegistrationWithMultiSecretSupport(oidcProperties);
    }
    
    @Test
    void testInitialization() {
        assertEquals(3, multiSecretClientRegistration.getTotalSecrets());
        assertEquals(0, multiSecretClientRegistration.getCurrentSecretIndex());
    }
    
    @Test
    void testGetCurrentClientRegistration() {
        ClientRegistration registration = multiSecretClientRegistration.getCurrentClientRegistration();
        
        assertNotNull(registration);
        assertEquals("test-client-id", registration.getClientId());
        assertEquals("secret1", registration.getClientSecret());
        assertEquals("oidc-0", registration.getRegistrationId());
    }
    
    @Test
    void testGetClientRegistrationByIndex() {
        ClientRegistration registration1 = multiSecretClientRegistration.getClientRegistrationByIndex(1);
        
        assertNotNull(registration1);
        assertEquals("secret2", registration1.getClientSecret());
        assertEquals("oidc-1", registration1.getRegistrationId());
        
        ClientRegistration registration2 = multiSecretClientRegistration.getClientRegistrationByIndex(2);
        
        assertNotNull(registration2);
        assertEquals("secret3", registration2.getClientSecret());
        assertEquals("oidc-2", registration2.getRegistrationId());
    }
    
    @Test
    void testSetCurrentSecretIndex() {
        multiSecretClientRegistration.setCurrentSecretIndex(1);
        assertEquals(1, multiSecretClientRegistration.getCurrentSecretIndex());
        
        ClientRegistration registration = multiSecretClientRegistration.getCurrentClientRegistration();
        assertEquals("secret2", registration.getClientSecret());
    }
    
    @Test
    void testInvalidSecretIndex() {
        multiSecretClientRegistration.setCurrentSecretIndex(10);
        assertEquals(0, multiSecretClientRegistration.getCurrentSecretIndex());
        
        assertNull(multiSecretClientRegistration.getClientRegistrationByIndex(-1));
        assertNull(multiSecretClientRegistration.getClientRegistrationByIndex(10));
    }
    
    @Test
    void testEmptySecretsThrowsException() {
        OidcProperties emptyProperties = new OidcProperties();
        emptyProperties.setClientSecrets(Arrays.asList());
        
        assertThrows(IllegalStateException.class, () -> {
            new ClientRegistrationWithMultiSecretSupport(emptyProperties);
        });
    }
}