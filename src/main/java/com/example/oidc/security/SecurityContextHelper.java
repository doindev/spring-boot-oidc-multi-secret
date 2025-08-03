package com.example.oidc.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Helper class to extract authentication information from different types of security contexts.
 * Supports OIDC, JWT, Basic Auth, and Microsoft Entra ID (Azure AD).
 */
public class SecurityContextHelper {
    
    private SecurityContextHelper() {
        // Static utility class
    }
    
    /**
     * Get the current username from the security context.
     * 
     * @param truncated whether to truncate domain from username
     * @return the username or null if not authenticated
     */
    public static String getUsername(boolean truncated) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        
        String username = extractUsername(authentication);
        
        if (truncated && username != null && username.contains("@")) {
            return username.substring(0, username.indexOf("@"));
        }
        
        return username;
    }
    
    /**
     * Get a specific claim/attribute value from the current authentication token.
     * 
     * @param claimName the name of the claim to retrieve
     * @return the claim value or null if not found
     */
    public static Object getClaim(String claimName) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return null;
        }
        
        Object principal = authentication.getPrincipal();
        
        // OIDC Token
        if (principal instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) principal;
            return oidcUser.getClaim(claimName);
        }
        
        // JWT Token
        if (authentication instanceof JwtAuthenticationToken) {
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            return jwt.getClaim(claimName);
        }
        
        // Microsoft Entra ID (often comes as JWT)
        if (principal instanceof Jwt) {
            Jwt jwt = (Jwt) principal;
            return jwt.getClaim(claimName);
        }
        
        return null;
    }
    
    /**
     * Get all claims from the current authentication token.
     * 
     * @return map of all claims or empty map if not available
     */
    public static Map<String, Object> getAllClaims() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return Collections.emptyMap();
        }
        
        Object principal = authentication.getPrincipal();
        
        // OIDC Token
        if (principal instanceof OidcUser) {
            return ((OidcUser) principal).getClaims();
        }
        
        // JWT Token
        if (authentication instanceof JwtAuthenticationToken) {
            return ((JwtAuthenticationToken) authentication).getToken().getClaims();
        }
        
        // Microsoft Entra ID
        if (principal instanceof Jwt) {
            return ((Jwt) principal).getClaims();
        }
        
        return Collections.emptyMap();
    }
    
    /**
     * Get the current user's roles/authorities.
     * 
     * @return set of role names
     */
    public static Set<String> getRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return Collections.emptySet();
        }
        
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
    }
    
    /**
     * Check if the current user has a specific role.
     * 
     * @param role the role to check (without ROLE_ prefix)
     * @return true if user has the role
     */
    public static boolean hasRole(String role) {
        String roleWithPrefix = role.startsWith("ROLE_") ? role : "ROLE_" + role;
        return getRoles().contains(roleWithPrefix);
    }
    
    /**
     * Get the authentication type of the current user.
     * 
     * @return the authentication type as string
     */
    public static String getAuthenticationType() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return "NONE";
        }
        
        Object principal = authentication.getPrincipal();
        
        if (principal instanceof OidcUser) {
            return "OIDC";
        } else if (authentication instanceof JwtAuthenticationToken || principal instanceof Jwt) {
            return "JWT";
        } else if (principal instanceof UserDetails) {
            return "BASIC_AUTH";
        } else if (principal instanceof String && "anonymousUser".equals(principal)) {
            return "ANONYMOUS";
        }
        
        return "UNKNOWN";
    }
    
    /**
     * Get email from various authentication types.
     * 
     * @return email address or null if not found
     */
    public static String getEmail() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return null;
        }
        
        Object principal = authentication.getPrincipal();
        
        // OIDC
        if (principal instanceof OidcUser) {
            return ((OidcUser) principal).getEmail();
        }
        
        // JWT (check common email claim names)
        Object emailClaim = getClaim("email");
        if (emailClaim != null) {
            return emailClaim.toString();
        }
        
        // Microsoft Entra ID specific claims
        emailClaim = getClaim("preferred_username");
        if (emailClaim != null && emailClaim.toString().contains("@")) {
            return emailClaim.toString();
        }
        
        emailClaim = getClaim("unique_name");
        if (emailClaim != null && emailClaim.toString().contains("@")) {
            return emailClaim.toString();
        }
        
        return null;
    }
    
    /**
     * Get user's full name from various authentication types.
     * 
     * @return full name or null if not found
     */
    public static String getFullName() {
        // Try standard claims first
        Object nameClaim = getClaim("name");
        if (nameClaim != null) {
            return nameClaim.toString();
        }
        
        // Try given_name + family_name
        Object givenName = getClaim("given_name");
        Object familyName = getClaim("family_name");
        if (givenName != null && familyName != null) {
            return givenName + " " + familyName;
        }
        
        // OIDC specific
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            return oidcUser.getFullName();
        }
        
        return null;
    }
    
    /**
     * Extract username from different authentication types.
     */
    private static String extractUsername(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        
        // OIDC User
        if (principal instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) principal;
            // Try preferred_username first, then email, then subject
            String username = oidcUser.getPreferredUsername();
            if (username == null) {
                username = oidcUser.getEmail();
            }
            if (username == null) {
                username = oidcUser.getSubject();
            }
            return username;
        }
        
        // JWT Token
        if (authentication instanceof JwtAuthenticationToken) {
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            // Try common username claims
            Object username = jwt.getClaim("preferred_username");
            if (username == null) {
                username = jwt.getClaim("username");
            }
            if (username == null) {
                username = jwt.getClaim("user_name");
            }
            if (username == null) {
                username = jwt.getClaim("email");
            }
            if (username == null) {
                username = jwt.getClaim("sub");
            }
            return username != null ? username.toString() : null;
        }
        
        // Basic Auth / UserDetails
        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }
        
        // Microsoft Entra ID (Azure AD) - often comes as JWT
        if (principal instanceof Jwt) {
            Jwt jwt = (Jwt) principal;
            // Azure AD specific claims
            Object username = jwt.getClaim("preferred_username");
            if (username == null) {
                username = jwt.getClaim("unique_name");
            }
            if (username == null) {
                username = jwt.getClaim("upn"); // User Principal Name
            }
            if (username == null) {
                username = jwt.getClaim("email");
            }
            return username != null ? username.toString() : null;
        }
        
        // Fallback to principal name
        return authentication.getName();
    }
    
    /**
     * Check if the current request is authenticated.
     * 
     * @return true if authenticated, false otherwise
     */
    public static boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && 
               authentication.isAuthenticated() && 
               !"anonymousUser".equals(authentication.getPrincipal());
    }
    
    /**
     * Get tenant/organization ID for multi-tenant scenarios (e.g., Microsoft Entra ID).
     * 
     * @return tenant ID or null if not found
     */
    public static String getTenantId() {
        // Common tenant claim names
        Object tenantClaim = getClaim("tid");
        if (tenantClaim == null) {
            tenantClaim = getClaim("tenant_id");
        }
        if (tenantClaim == null) {
            tenantClaim = getClaim("tenantid");
        }
        return tenantClaim != null ? tenantClaim.toString() : null;
    }
}