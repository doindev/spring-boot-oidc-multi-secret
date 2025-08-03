package com.example.oidc.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "app.oidc")
public class OidcProperties {
    
    private String issuerUri;
    private String clientId;
    private List<String> clientSecrets;
    private String redirectUri;
    private List<String> scopes;
    private long secretRotationIntervalMs = 60000; // Default: 1 minute
    private String authorizationUri;
    private String tokenUri;
    private String userInfoUri;
    private String jwkSetUri;
    private String endSessionUri;
    private String postLogoutRedirectUri;
}