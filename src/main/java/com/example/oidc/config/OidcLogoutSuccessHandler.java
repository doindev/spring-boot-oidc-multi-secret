package com.example.oidc.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Custom logout success handler for OIDC RP-Initiated Logout.
 * Redirects to the OIDC provider's end_session_endpoint to perform single logout.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "security.type", havingValue = "oidc")
public class OidcLogoutSuccessHandler implements LogoutSuccessHandler {
    
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OidcProperties oidcProperties;
    
    public OidcLogoutSuccessHandler(
    	ClientRegistrationRepository clientRegistrationRepository,
        OidcProperties oidcProperties
    ) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.oidcProperties = oidcProperties;
    }
    
    @Override
    public void onLogoutSuccess(
		HttpServletRequest request, 
		HttpServletResponse response,
		Authentication authentication
	) throws IOException {
        
        // Default redirect if not OIDC authenticated
        String targetUrl = "/";
        
        // Check if this was an OIDC authentication
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();
            
            ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(registrationId);
            
            if (clientRegistration != null) {
                // Get the OIDC provider's end session endpoint
                String endSessionEndpoint = getEndSessionEndpoint(clientRegistration);
                
                if (endSessionEndpoint != null) {
                    // Build the logout URL with required parameters
                    targetUrl = buildLogoutUrl(endSessionEndpoint, authentication, request);
                    log.info("Redirecting to OIDC provider logout: {}", targetUrl);
                }
            }
        }
        
        response.sendRedirect(targetUrl);
    }
    
    private String getEndSessionEndpoint(ClientRegistration clientRegistration) {
        // Try to get from provider metadata
        Object endSessionEndpoint = clientRegistration.getProviderDetails()
                .getConfigurationMetadata()
                .get("end_session_endpoint");
        
        if (endSessionEndpoint != null) {
            return endSessionEndpoint.toString();
        }
        
        // Fallback to configured value if available
        if (oidcProperties.getEndSessionUri() != null) {
            return oidcProperties.getEndSessionUri();
        }
        
        // Common patterns for different providers
        String issuerUri = clientRegistration.getProviderDetails().getIssuerUri();
        if (issuerUri != null) {
            // Keycloak pattern
            if (issuerUri.contains("keycloak")) {
                return issuerUri + "/protocol/openid-connect/logout";
            }
            // Auth0 pattern
            if (issuerUri.contains("auth0.com")) {
                return issuerUri + "/v2/logout";
            }
            // Okta pattern
            if (issuerUri.contains("okta.com")) {
                return issuerUri + "/v1/logout";
            }
        }
        
        log.warn("Could not determine end_session_endpoint for OIDC provider");
        return null;
    }
    
    private String buildLogoutUrl(String endSessionEndpoint, Authentication authentication,
                                 HttpServletRequest request) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(endSessionEndpoint);
        
        // Add id_token_hint if available
        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            String idToken = oidcUser.getIdToken().getTokenValue();
            builder.queryParam("id_token_hint", idToken);
        }
        
        // Add post_logout_redirect_uri
        String postLogoutRedirectUri = buildPostLogoutRedirectUri(request);
        builder.queryParam("post_logout_redirect_uri", 
                URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8));
        
        // Some providers require client_id
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        ClientRegistration registration = clientRegistrationRepository
                .findByRegistrationId(oauthToken.getAuthorizedClientRegistrationId());
        if (registration != null) {
            builder.queryParam("client_id", registration.getClientId());
        }
        
        return builder.build().toUriString();
    }
    
    private String buildPostLogoutRedirectUri(HttpServletRequest request) {
        // Build the full URL for post-logout redirect
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();
        
        StringBuilder url = new StringBuilder();
        url.append(scheme).append("://").append(serverName);
        
        // Only add port if it's not the default for the scheme
        if ((scheme.equals("http") && serverPort != 80) || 
            (scheme.equals("https") && serverPort != 443)) {
            url.append(":").append(serverPort);
        }
        
        url.append(contextPath);
        
        // Use configured post-logout redirect URI if available
        if (oidcProperties.getPostLogoutRedirectUri() != null) {
            return oidcProperties.getPostLogoutRedirectUri();
        }
        
        return url.toString();
    }
}