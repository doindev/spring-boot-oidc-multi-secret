package com.example.entra;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Custom OAuth2 user service for Microsoft Entra ID.
 * Extracts Entra-specific claims and validates group/role membership.
 */
@Slf4j
public class EntraOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    
    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    private final List<String> allowedGroups;
    private final List<String> allowedAppRoles;
    
    public EntraOAuth2UserService(List<String> allowedGroups, List<String> allowedAppRoles) {
        this.allowedGroups = allowedGroups != null ? allowedGroups : new ArrayList<>();
        this.allowedAppRoles = allowedAppRoles != null ? allowedAppRoles : new ArrayList<>();
    }
    
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // First load the user using the default service
        OAuth2User oauth2User = delegate.loadUser(userRequest);
        
        // Extract authorities from the access token
        Collection<GrantedAuthority> authorities = new HashSet<>(oauth2User.getAuthorities());
        OAuth2AccessToken accessToken = userRequest.getAccessToken();
        
        try {
            // Parse the access token as JWT to extract Entra-specific claims
            Map<String, Object> additionalAttributes = extractEntraClaimsFromToken(accessToken.getTokenValue());
            
            // Extract and add group authorities
            List<String> groups = extractListClaim(additionalAttributes, "groups");
            groups.forEach(group -> authorities.add(new SimpleGrantedAuthority("GROUP_" + group)));
            
            // Extract and add role authorities
            List<String> roles = extractListClaim(additionalAttributes, "roles");
            roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
            
            // Extract and add app role authorities
            List<String> appRoles = extractListClaim(additionalAttributes, "approles");
            appRoles.forEach(appRole -> authorities.add(new SimpleGrantedAuthority("APPROLE_" + appRole.toUpperCase())));
            
            // Check access
            if (!checkAccess(groups, appRoles)) {
                log.warn("User {} does not have required groups or app roles", oauth2User.getName());
                throw new OAuth2AuthenticationException(
                    new OAuth2Error("access_denied", "User does not have required groups or roles", null)
                );
            }
            
            // Merge attributes
            Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());
            attributes.putAll(additionalAttributes);
            
            // Determine the principal attribute name
            String principalAttributeName = determinePrincipalAttributeName(attributes);
            
            return new DefaultOAuth2User(authorities, attributes, principalAttributeName);
            
        } catch (Exception e) {
            log.error("Error processing Entra user", e);
            if (e instanceof OAuth2AuthenticationException) {
                throw (OAuth2AuthenticationException) e;
            }
            throw new OAuth2AuthenticationException(
                new OAuth2Error("entra_processing_error", "Error processing Entra user: " + e.getMessage(), null)
            );
        }
    }
    
    private Map<String, Object> extractEntraClaimsFromToken(String tokenValue) {
        try {
            // Simple JWT parsing - in production, you might want to validate the signature
            String[] parts = tokenValue.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
                // Parse JSON payload - using simple approach, consider using Jackson
                Map<String, Object> claims = parseJsonToMap(payload);
                return claims;
            }
        } catch (Exception e) {
            log.warn("Could not extract claims from access token", e);
        }
        return new HashMap<>();
    }
    
    @SuppressWarnings("unchecked")
    private Map<String, Object> parseJsonToMap(String json) {
        // This is a simplified implementation - in production use Jackson or Gson
        Map<String, Object> map = new HashMap<>();
        json = json.trim().substring(1, json.length() - 1); // Remove { }
        String[] pairs = json.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
        
        for (String pair : pairs) {
            String[] keyValue = pair.split(":", 2);
            if (keyValue.length == 2) {
                String key = keyValue[0].trim().replaceAll("\"", "");
                String value = keyValue[1].trim();
                
                if (value.startsWith("[")) {
                    // Array value
                    List<String> list = Arrays.stream(value.substring(1, value.length() - 1).split(","))
                        .map(s -> s.trim().replaceAll("\"", ""))
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toList());
                    map.put(key, list);
                } else if (value.startsWith("\"")) {
                    // String value
                    map.put(key, value.replaceAll("\"", ""));
                } else {
                    // Other value (number, boolean, etc.)
                    map.put(key, value);
                }
            }
        }
        
        return map;
    }
    
    private String determinePrincipalAttributeName(Map<String, Object> attributes) {
        // Entra ID typically uses these claims for the principal
        if (attributes.containsKey("preferred_username")) {
            return "preferred_username";
        } else if (attributes.containsKey("upn")) {
            return "upn";
        } else if (attributes.containsKey("email")) {
            return "email";
        } else if (attributes.containsKey("name")) {
            return "name";
        }
        return "sub"; // Fallback to subject
    }
    
    @SuppressWarnings("unchecked")
    private List<String> extractListClaim(Map<String, Object> claims, String claimName) {
        Object claim = claims.get(claimName);
        if (claim instanceof List) {
            return ((List<?>) claim).stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .collect(Collectors.toList());
        } else if (claim instanceof String) {
            return List.of((String) claim);
        }
        return new ArrayList<>();
    }
    
    private boolean checkAccess(List<String> userGroups, List<String> userAppRoles) {
        // If no restrictions are configured, allow access
        if (allowedGroups.isEmpty() && allowedAppRoles.isEmpty()) {
            return true;
        }
        
        // Check groups
        if (!allowedGroups.isEmpty() && userGroups.stream().anyMatch(allowedGroups::contains)) {
            return true;
        }
        
        // Check app roles
        if (!allowedAppRoles.isEmpty() && userAppRoles.stream().anyMatch(allowedAppRoles::contains)) {
            return true;
        }
        
        return false;
    }
}