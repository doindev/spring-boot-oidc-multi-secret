package com.example.entra;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Custom JWT authentication converter for Microsoft Entra ID tokens.
 * Handles Entra-specific claims like groups and app roles.
 */
@Slf4j
public class EntraJwtAuthenticationConverter extends JwtAuthenticationConverter {
    
    private static final String GROUPS_CLAIM = "groups";
    private static final String ROLES_CLAIM = "roles";
    private static final String APP_ROLES_CLAIM = "approles";
    private static final String PREFERRED_USERNAME_CLAIM = "preferred_username";
    private static final String UPN_CLAIM = "upn";
    
    private List<String> allowedGroups = new ArrayList<>();
    private List<String> allowedAppRoles = new ArrayList<>();
    
    public EntraJwtAuthenticationConverter() {
        // Set custom authorities converter
        setJwtGrantedAuthoritiesConverter(jwt -> extractAuthorities(jwt));
        
        // Set custom principal claim
        setPrincipalClaimName(PREFERRED_USERNAME_CLAIM);
    }
    
    public void setAllowedGroups(List<String> allowedGroups) {
        this.allowedGroups = allowedGroups != null ? allowedGroups : new ArrayList<>();
    }
    
    public void setAllowedAppRoles(List<String> allowedAppRoles) {
        this.allowedAppRoles = allowedAppRoles != null ? allowedAppRoles : new ArrayList<>();
    }
    
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        String principal = extractPrincipal(jwt);
        
        // Check if user has required groups or roles
        if (!allowedGroups.isEmpty() || !allowedAppRoles.isEmpty()) {
            boolean hasAccess = checkAccess(jwt);
            if (!hasAccess) {
                log.warn("User {} does not have required groups or app roles", principal);
                authorities = new ArrayList<>(); // Remove all authorities if access denied
            }
        }
        
        return new JwtAuthenticationToken(jwt, authorities, principal);
    }
    
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        
        // Extract groups
        List<String> groups = extractClaim(jwt, GROUPS_CLAIM);
        groups.forEach(group -> {
            authorities.add(new SimpleGrantedAuthority("GROUP_" + group));
            log.debug("Added group authority: GROUP_{}", group);
        });
        
        // Extract roles
        List<String> roles = extractClaim(jwt, ROLES_CLAIM);
        roles.forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
            log.debug("Added role authority: ROLE_{}", role.toUpperCase());
        });
        
        // Extract app roles
        List<String> appRoles = extractClaim(jwt, APP_ROLES_CLAIM);
        appRoles.forEach(appRole -> {
            authorities.add(new SimpleGrantedAuthority("APPROLE_" + appRole.toUpperCase()));
            log.debug("Added app role authority: APPROLE_{}", appRole.toUpperCase());
        });
        
        // Also use default scope authorities
        JwtGrantedAuthoritiesConverter defaultConverter = new JwtGrantedAuthoritiesConverter();
        authorities.addAll(defaultConverter.convert(jwt));
        
        return authorities;
    }
    
    private String extractPrincipal(Jwt jwt) {
        // Try preferred_username first, then upn, then email
        String principal = jwt.getClaimAsString(PREFERRED_USERNAME_CLAIM);
        if (principal == null) {
            principal = jwt.getClaimAsString(UPN_CLAIM);
        }
        if (principal == null) {
            principal = jwt.getClaimAsString("email");
        }
        if (principal == null) {
            principal = jwt.getSubject();
        }
        return principal;
    }
    
    private boolean checkAccess(Jwt jwt) {
        // Check groups
        if (!allowedGroups.isEmpty()) {
            List<String> userGroups = extractClaim(jwt, GROUPS_CLAIM);
            boolean hasGroup = userGroups.stream()
                .anyMatch(allowedGroups::contains);
            if (hasGroup) {
                return true;
            }
        }
        
        // Check app roles
        if (!allowedAppRoles.isEmpty()) {
            List<String> userAppRoles = extractClaim(jwt, APP_ROLES_CLAIM);
            boolean hasAppRole = userAppRoles.stream()
                .anyMatch(allowedAppRoles::contains);
            if (hasAppRole) {
                return true;
            }
        }
        
        // If both lists are empty, allow access
        return allowedGroups.isEmpty() && allowedAppRoles.isEmpty();
    }
    
    @SuppressWarnings("unchecked")
    private List<String> extractClaim(Jwt jwt, String claimName) {
        Object claim = jwt.getClaim(claimName);
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
}