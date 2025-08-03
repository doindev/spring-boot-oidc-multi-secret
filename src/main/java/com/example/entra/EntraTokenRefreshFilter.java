package com.example.entra;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Filter to automatically refresh expired Microsoft Entra ID tokens.
 * Specifically handles Entra ID token refresh scenarios.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "security.type", havingValue = "entra")
public class EntraTokenRefreshFilter extends OncePerRequestFilter {
    
    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    private final Clock clock = Clock.systemUTC();
    private final Duration clockSkew = Duration.ofSeconds(60);
    
    public EntraTokenRefreshFilter(
            OAuth2AuthorizedClientManager authorizedClientManager,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
        this.authorizedClientManager = authorizedClientManager;
        this.authorizedClientRepository = authorizedClientRepository;
    }
    
    @Override
    protected void doFilterInternal(
            HttpServletRequest request, 
            HttpServletResponse response, 
            FilterChain filterChain) throws ServletException, IOException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
            String registrationId = oauth2Token.getAuthorizedClientRegistrationId();
            
            // Only process if it's an Entra registration
            if (!"entra".equals(registrationId)) {
                filterChain.doFilter(request, response);
                return;
            }
            
            boolean idTokenExpired = false;
            if (oauth2Token.getPrincipal() instanceof OidcUser) {
                OidcUser oidcUser = (OidcUser) oauth2Token.getPrincipal();
                OidcIdToken idToken = oidcUser.getIdToken();
                if (idToken != null && idToken.getExpiresAt() != null) {
                    idTokenExpired = isTokenExpired(idToken.getExpiresAt());
                }
            }
            
            OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                registrationId, authentication, request);
            
            boolean accessTokenExpired = false;
            if (authorizedClient != null) {
                OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
                accessTokenExpired = isTokenExpired(accessToken);
            }
            
            if (accessTokenExpired || idTokenExpired) {
                log.info("Entra token expired for user: {} (access: {}, id: {}), attempting refresh", 
                        authentication.getName(), accessTokenExpired, idTokenExpired);
                
                if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {
                    OAuth2AuthorizedClient refreshedClient = refreshToken(
                        authorizedClient, oauth2Token, request, response);
                    
                    if (refreshedClient != null) {
                        log.info("Successfully refreshed Entra token for user: {}", authentication.getName());
                        
                        authorizedClientRepository.saveAuthorizedClient(
                            refreshedClient, authentication, request, response);
                        
                        filterChain.doFilter(request, response);
                        return;
                    }
                }
                
                log.warn("Entra token expired and cannot refresh for user: {}", authentication.getName());
                
                // For API endpoints, return 401
                if (request.getRequestURI().startsWith("/api/")) {
                    SecurityContextHolder.clearContext();
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, 
                        "Entra token expired and refresh failed");
                    return;
                }
            }
        }
        
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
        Instant now = clock.instant();
        return now.isAfter(expiresAt.minus(clockSkew));
    }
    
    private OAuth2AuthorizedClient refreshToken(
            OAuth2AuthorizedClient authorizedClient,
            OAuth2AuthenticationToken authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
            
            if (refreshToken == null || refreshToken.getTokenValue() == null) {
                log.debug("No refresh token available for Entra client");
                return null;
            }
            
            OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withAuthorizedClient(authorizedClient)
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();
            
            OAuth2AuthorizedClient refreshedClient = authorizedClientManager.authorize(authorizeRequest);
            
            if (refreshedClient != null && refreshedClient.getAccessToken() != null) {
                return refreshedClient;
            }
            
        } catch (Exception e) {
            log.error("Error refreshing Entra token", e);
        }
        
        return null;
    }
}