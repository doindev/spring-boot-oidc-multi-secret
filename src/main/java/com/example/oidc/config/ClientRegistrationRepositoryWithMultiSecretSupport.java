package com.example.oidc.config;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@ConditionalOnProperty(name = "security.type", havingValue = "oidc")
public class ClientRegistrationRepositoryWithMultiSecretSupport implements ClientRegistrationRepository {
    
    private final ClientRegistrationWithMultiSecretSupport multiSecretClientRegistration;
    private final OidcProperties oidcProperties;
    private final RestTemplate restTemplate;
    private ScheduledExecutorService scheduler;
    
    public ClientRegistrationRepositoryWithMultiSecretSupport(
    	ClientRegistrationWithMultiSecretSupport multiSecretClientRegistration,
    	OidcProperties oidcProperties
	) {
        this.multiSecretClientRegistration = multiSecretClientRegistration;
        this.oidcProperties = oidcProperties;
        this.restTemplate = new RestTemplate();
    }
    
    @PostConstruct
    public void init() {
        if (multiSecretClientRegistration.getTotalSecrets() > 1) {
            log.info("Multiple secrets detected ({}), starting internal polling process", 
                    multiSecretClientRegistration.getTotalSecrets());
            
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread thread = new Thread(r);
                thread.setName("oidc-secret-rotation");
                thread.setDaemon(true);
                return thread;
            });
            
            long intervalMs = oidcProperties.getSecretRotationIntervalMs();
            scheduler.scheduleWithFixedDelay(this::checkAndRotateSecrets, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
        } else {
            log.info("Single secret configured, polling process not started");
        }
    }
    
    @PreDestroy
    public void destroy() {
        if (scheduler != null) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
    
    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        // Always return the current active client registration
        return multiSecretClientRegistration.getCurrentClientRegistration();
    }
    
    private void checkAndRotateSecrets() {
        try {
            log.debug("Starting secret rotation check");
            
            int totalSecrets = multiSecretClientRegistration.getTotalSecrets();
            int currentIndex = multiSecretClientRegistration.getCurrentSecretIndex();
            
            // Try current secret first
            if (testSecret(currentIndex)) {
                log.debug("Current secret at index {} is still valid", currentIndex);
                return;
            }
            
            log.warn("Current secret at index {} failed validation, attempting rotation", currentIndex);
            
            // Try other secrets
            for (int i = 0; i < totalSecrets; i++) {
                if (i != currentIndex && testSecret(i)) {
                    multiSecretClientRegistration.setCurrentSecretIndex(i);
                    log.info("Successfully rotated to secret at index {}", i);
                    return;
                }
            }
            
            log.error("All {} configured secrets failed validation!", totalSecrets);
        } catch (Exception e) {
            log.error("Error during secret rotation check", e);
        }
    }
    
    private boolean testSecret(int secretIndex) {
        try {
            ClientRegistration registration = multiSecretClientRegistration.getClientRegistrationByIndex(secretIndex);
            if (registration == null) {
                return false;
            }
            
            // Attempt to get a client credentials token to validate the secret
            String tokenEndpoint = registration.getProviderDetails().getTokenUri();
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            // Add Basic Auth header
            String credentials = registration.getClientId() + ":" + registration.getClientSecret();
            String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
            headers.add("Authorization", "Basic " + encodedCredentials);
            
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("grant_type", "client_credentials");
            params.add("scope", String.join(" ", registration.getScopes()));
            
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                tokenEndpoint,
                HttpMethod.POST,
                request,
                String.class
            );
            
            boolean success = response.getStatusCode() == HttpStatus.OK;
            if (success) {
                log.debug("Secret at index {} validated successfully", secretIndex);
            }
            return success;
            
        } catch (Exception e) {
            log.debug("Secret at index {} validation failed: {}", secretIndex, e.getMessage());
            return false;
        }
    }
}