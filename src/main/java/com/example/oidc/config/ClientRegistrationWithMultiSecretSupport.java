package com.example.oidc.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@ConditionalOnProperty(name = "security.type", havingValue = "oidc")
public class ClientRegistrationWithMultiSecretSupport {
    
    private final OidcProperties oidcProperties;
    private final List<ClientRegistration> clientRegistrations = new ArrayList<>();
    private int currentSecretIndex = 0;
    
    public ClientRegistrationWithMultiSecretSupport(OidcProperties oidcProperties) {
        this.oidcProperties = oidcProperties;
        initializeClientRegistrations();
    }
    
    private void initializeClientRegistrations() {
        List<String> secrets = oidcProperties.getClientSecrets();
        if (secrets == null || secrets.isEmpty()) {
            throw new IllegalStateException("At least one client secret must be configured");
        }
        
        for (int i = 0; i < secrets.size(); i++) {
            ClientRegistration registration = createClientRegistration(secrets.get(i), i);
            clientRegistrations.add(registration);
        }
        
        log.info("Initialized {} client registrations for secret rotation", clientRegistrations.size());
    }
    
    private ClientRegistration createClientRegistration(String clientSecret, int index) {
        return ClientRegistration.withRegistrationId("oidc-" + index)
                .clientId(oidcProperties.getClientId())
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(oidcProperties.getRedirectUri())
                .scope(oidcProperties.getScopes().toArray(new String[0]))
                .authorizationUri(oidcProperties.getAuthorizationUri())
                .tokenUri(oidcProperties.getTokenUri())
                .userInfoUri(oidcProperties.getUserInfoUri())
                .jwkSetUri(oidcProperties.getJwkSetUri())
                .userNameAttributeName("preferred_username")
                .clientName("OIDC Client " + index)
                .build();
    }
    
    public ClientRegistration getCurrentClientRegistration() {
        return clientRegistrations.get(currentSecretIndex);
    }
    
    public ClientRegistration getClientRegistrationByIndex(int index) {
        if (index >= 0 && index < clientRegistrations.size()) {
            return clientRegistrations.get(index);
        }
        return null;
    }
    
    public void setCurrentSecretIndex(int index) {
        if (index >= 0 && index < clientRegistrations.size()) {
            this.currentSecretIndex = index;
            log.info("Switched to client secret at index: {}", index);
        }
    }
    
    public int getCurrentSecretIndex() {
        return currentSecretIndex;
    }
    
    public int getTotalSecrets() {
        return clientRegistrations.size();
    }
}