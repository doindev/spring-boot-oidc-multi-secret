package com.example.oidc.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SecurityContextHelperTest {
    
    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }
    
    @Test
    void testGetUsername_WithTruncation() {
        // Test with email format username
        setBasicAuthContext("john.doe@example.com");
        
        // Truncated should remove @example.com
        assertEquals("john.doe", SecurityContextHelper.getUsername(true));
        
        // Not truncated should keep full username
        assertEquals("john.doe@example.com", SecurityContextHelper.getUsername(false));
    }
    
    @Test
    void testGetUsername_WithoutAtSymbol() {
        // Test with username that doesn't have @
        setBasicAuthContext("simpleuser");
        
        // Both truncated and non-truncated should return same value
        assertEquals("simpleuser", SecurityContextHelper.getUsername(true));
        assertEquals("simpleuser", SecurityContextHelper.getUsername(false));
    }
    
    @Test
    void testGetUsername_WithMultipleAtSymbols() {
        // Test edge case with multiple @ symbols
        setBasicAuthContext("user@dept@company.com");
        
        // Should only remove from first @ onwards
        assertEquals("user", SecurityContextHelper.getUsername(true));
        assertEquals("user@dept@company.com", SecurityContextHelper.getUsername(false));
    }
    
    @Test
    void testGetUsername_NotAuthenticated() {
        // No authentication set
        assertNull(SecurityContextHelper.getUsername(true));
        assertNull(SecurityContextHelper.getUsername(false));
    }
    
    @Test
    void testGetAuthenticationType() {
        // Test Basic Auth
        setBasicAuthContext("user");
        assertEquals("BASIC_AUTH", SecurityContextHelper.getAuthenticationType());
        
        // Clear and test no auth
        SecurityContextHolder.clearContext();
        assertEquals("NONE", SecurityContextHelper.getAuthenticationType());
    }
    
    @Test
    void testGetRoles() {
        setBasicAuthContext("user", "ROLE_USER", "ROLE_ADMIN");
        
        Set<String> roles = SecurityContextHelper.getRoles();
        assertEquals(2, roles.size());
        assertTrue(roles.contains("ROLE_USER"));
        assertTrue(roles.contains("ROLE_ADMIN"));
    }
    
    @Test
    void testHasRole() {
        setBasicAuthContext("user", "ROLE_USER", "ROLE_ADMIN");
        
        // Test with and without ROLE_ prefix
        assertTrue(SecurityContextHelper.hasRole("USER"));
        assertTrue(SecurityContextHelper.hasRole("ROLE_USER"));
        assertTrue(SecurityContextHelper.hasRole("ADMIN"));
        assertFalse(SecurityContextHelper.hasRole("MANAGER"));
    }
    
    @Test
    void testIsAuthenticated() {
        assertFalse(SecurityContextHelper.isAuthenticated());
        
        setBasicAuthContext("user");
        assertTrue(SecurityContextHelper.isAuthenticated());
        
        // Test anonymous user
        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("anonymousUser", null)
        );
        assertFalse(SecurityContextHelper.isAuthenticated());
    }
    
    @Test
    void testOidcUser() {
        // Create OIDC user with claims
        Map<String, Object> claims = Map.of(
            "sub", "12345",
            "preferred_username", "john.doe@company.com",
            "email", "john.doe@email.com",
            "name", "John Doe",
            "given_name", "John",
            "family_name", "Doe"
        );
        
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusSeconds(3600), claims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(
            List.of(new SimpleGrantedAuthority("ROLE_USER")),
            idToken,
            "preferred_username"
        );
        
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
            oidcUser, null, oidcUser.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        // Test username extraction with truncation
        assertEquals("john.doe", SecurityContextHelper.getUsername(true));
        assertEquals("john.doe@company.com", SecurityContextHelper.getUsername(false));
        
        // Test other methods
        assertEquals("john.doe@email.com", SecurityContextHelper.getEmail());
        assertEquals("John Doe", SecurityContextHelper.getFullName());
        assertEquals("OIDC", SecurityContextHelper.getAuthenticationType());
        assertEquals("12345", SecurityContextHelper.getClaim("sub"));
        assertTrue(SecurityContextHelper.getAllClaims().containsKey("preferred_username"));
    }
    
    @Test
    void testGetFullName_FromSeparateNameClaims() {
        // Test constructing full name from given_name + family_name
        Map<String, Object> claims = Map.of(
            "sub", "67890",
            "given_name", "Jane",
            "family_name", "Smith"
        );
        
        OidcIdToken idToken = new OidcIdToken("token", Instant.now(), Instant.now().plusSeconds(3600), claims);
        DefaultOidcUser oidcUser = new DefaultOidcUser(
            List.of(new SimpleGrantedAuthority("ROLE_USER")),
            idToken
        );
        
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
            oidcUser, null, oidcUser.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        assertEquals("Jane Smith", SecurityContextHelper.getFullName());
    }
    
    private void setBasicAuthContext(String username, String... roles) {
        List<SimpleGrantedAuthority> authorities = List.of(roles)
            .stream()
            .map(SimpleGrantedAuthority::new)
            .toList();
        
        org.springframework.security.core.userdetails.User user = 
            new org.springframework.security.core.userdetails.User(
                username, "password", authorities
            );
        
        UsernamePasswordAuthenticationToken auth = 
            new UsernamePasswordAuthenticationToken(user, null, authorities);
        
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}