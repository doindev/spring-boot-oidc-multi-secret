package com.example.oidc.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Filter to automatically refresh expired OIDC tokens.
 * If refresh fails, returns 401 for API endpoints.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "security.type", havingValue = "oidc")
public class OidcTokenRefreshFilter extends OncePerRequestFilter {
    
    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final Clock clock = Clock.systemUTC();
    private final Duration clockSkew = Duration.ofSeconds(60); // 60 seconds clock skew
    
    public OidcTokenRefreshFilter(
    	OAuth2AuthorizedClientManager authorizedClientManager,
		OAuth2AuthorizedClientRepository authorizedClientRepository,
        ClientRegistrationRepository clientRegistrationRepository
	) {
        this.authorizedClientManager = authorizedClientManager;
        this.authorizedClientRepository = authorizedClientRepository;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }
    
    @Override
    protected void doFilterInternal(
		HttpServletRequest request, 
		HttpServletResponse response, 
		FilterChain filterChain
	) throws ServletException, IOException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Check if it's OIDC authentication
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
            String registrationId = oauth2Token.getAuthorizedClientRegistrationId();
            
            // Check if principal is an OIDC user with ID token
            boolean idTokenExpired = false;
            if (oauth2Token.getPrincipal() instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) oauth2Token.getPrincipal();
                OidcIdToken idToken = oidcUser.getIdToken();
                if (idToken != null && idToken.getExpiresAt() != null) {
                    idTokenExpired = isTokenExpired(idToken.getExpiresAt());
                }
            }
            
            // Get the authorized client
            OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                registrationId, authentication, request);
            
            boolean accessTokenExpired = false;
            if (authorizedClient != null) {
                OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
                accessTokenExpired = isTokenExpired(accessToken);
            }
            
            // Check if either token is expired
            if (accessTokenExpired || idTokenExpired) {
                log.info("Token expired for user: {} (access: {}, id: {}), attempting refresh", 
                        authentication.getName(), accessTokenExpired, idTokenExpired);
                
                // Only try to refresh if we have a refresh token and authorized client
                if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {
                    // Try to refresh the token
                    OAuth2AuthorizedClient refreshedClient = refreshToken(
                        authorizedClient, oauth2Token, request, response);
                    
                    if (refreshedClient != null) {
                        log.info("Successfully refreshed token for user: {}", authentication.getName());
                        
                        // Save the refreshed client
                        authorizedClientRepository.saveAuthorizedClient(
                            refreshedClient, authentication, request, response);
                        
                        // Continue with the request
                        filterChain.doFilter(request, response);
                        return;
                    }
                }
                
                log.warn("Token expired and cannot refresh for user: {}", authentication.getName());
                
                // Only return 401 for API endpoints
                if (request.getRequestURI().startsWith("/api/")) {
                    SecurityContextHolder.clearContext();
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, 
                        "Token expired and refresh failed");
                    return;
                }
            }
        }
        
        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }
    
    private boolean isTokenExpired(OAuth2AccessToken accessToken) {
        if (accessToken == null || accessToken.getExpiresAt() == null) {
            return false;
        }
        
        return isTokenExpired(accessToken.getExpiresAt());
    }
    
    private boolean isTokenExpired(Instant expiresAt) {
        if (expiresAt == null) {
            return false;
        }
        
        // Check if token is expired or will expire within the clock skew window
        Instant now = clock.instant();
        return now.isAfter(expiresAt.minus(clockSkew));
    }
    
    private OAuth2AuthorizedClient refreshToken(
		OAuth2AuthorizedClient authorizedClient,
		OAuth2AuthenticationToken authentication,
		HttpServletRequest request,
		HttpServletResponse response
   	) {
        try {
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
            
            // Check if we have a refresh token
            if (refreshToken == null || refreshToken.getTokenValue() == null) {
                log.debug("No refresh token available for client: {}", 
                    authorizedClient.getClientRegistration().getRegistrationId());
                return null;
            }
            
            // Create authorization request
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withAuthorizedClient(authorizedClient)
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();
            
            // Use the authorized client manager to refresh the token
            OAuth2AuthorizedClient refreshedClient = authorizedClientManager.authorize(authorizeRequest);
            
            if (refreshedClient != null && refreshedClient.getAccessToken() != null) {
                return refreshedClient;
            }
            
        } catch (Exception e) {
            log.error("Error refreshing token for client: {}", 
                authorizedClient.getClientRegistration().getRegistrationId(), e);
        }
        
        return null;
    }
}