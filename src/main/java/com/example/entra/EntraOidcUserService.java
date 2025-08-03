package com.example.entra;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Custom OIDC user service for Microsoft Entra ID.
 * Handles ID token claims specific to Entra.
 */
@Slf4j
public class EntraOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
    
    private final OidcUserService delegate = new OidcUserService();
    private final List<String> allowedGroups;
    private final List<String> allowedAppRoles;
    
    public EntraOidcUserService(List<String> allowedGroups, List<String> allowedAppRoles) {
        this.allowedGroups = allowedGroups != null ? allowedGroups : new ArrayList<>();
        this.allowedAppRoles = allowedAppRoles != null ? allowedAppRoles : new ArrayList<>();
    }
    
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // Load user using default service
        OidcUser oidcUser = delegate.loadUser(userRequest);
        
        // Extract authorities from ID token
        Collection<GrantedAuthority> authorities = new HashSet<>(oidcUser.getAuthorities());
        OidcIdToken idToken = oidcUser.getIdToken();
        
        // Extract groups from ID token
        List<String> groups = extractListClaim(idToken.getClaims(), "groups");
        groups.forEach(group -> authorities.add(new SimpleGrantedAuthority("GROUP_" + group)));
        
        // Extract roles from ID token
        List<String> roles = extractListClaim(idToken.getClaims(), "roles");
        roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
        
        // Extract app roles from ID token
        List<String> appRoles = extractListClaim(idToken.getClaims(), "approles");
        appRoles.forEach(appRole -> authorities.add(new SimpleGrantedAuthority("APPROLE_" + appRole.toUpperCase())));
        
        // Check access
        if (!checkAccess(groups, appRoles)) {
            log.warn("User {} does not have required groups or app roles", oidcUser.getName());
            throw new OAuth2AuthenticationException(
                new OAuth2Error("access_denied", "User does not have required groups or roles", null)
            );
        }
        
        // Determine principal claim
        String principalClaimName = determinePrincipalClaimName(idToken.getClaims());
        
        return new DefaultOidcUser(authorities, idToken, oidcUser.getUserInfo(), principalClaimName);
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
    
    private String determinePrincipalClaimName(Map<String, Object> claims) {
        if (claims.containsKey("preferred_username")) {
            return "preferred_username";
        } else if (claims.containsKey("upn")) {
            return "upn";
        } else if (claims.containsKey("email")) {
            return "email";
        } else if (claims.containsKey("name")) {
            return "name";
        }
        return "sub";
    }
    
    private boolean checkAccess(List<String> userGroups, List<String> userAppRoles) {
        if (allowedGroups.isEmpty() && allowedAppRoles.isEmpty()) {
            return true;
        }
        
        if (!allowedGroups.isEmpty() && userGroups.stream().anyMatch(allowedGroups::contains)) {
            return true;
        }
        
        if (!allowedAppRoles.isEmpty() && userAppRoles.stream().anyMatch(allowedAppRoles::contains)) {
            return true;
        }
        
        return false;
    }
}