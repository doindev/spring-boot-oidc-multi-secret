package com.example.oidc.security;

import com.example.oidc.config.OidcProperties;
import com.example.oidc.controller.ApiController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.context.annotation.Import;
import com.example.oidc.config.TestSecurityConfig;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestSecurityConfig.class)
class ApiAuthenticationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void testApi_NoAuthentication_Returns401() throws Exception {
        mockMvc.perform(get("/api/user"))
            .andExpect(status().isUnauthorized());
        
        mockMvc.perform(get("/api/user-v2"))
            .andExpect(status().isUnauthorized());
        
        mockMvc.perform(get("/api/health"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void testApi_ExpiredSession_Returns401() throws Exception {
        // Create a session
        MockHttpSession session = new MockHttpSession();
        session.setMaxInactiveInterval(1); // 1 second timeout
        
        // Make initial authenticated request
        mockMvc.perform(get("/api/health")
                .session(session)
                .with(SecurityMockMvcRequestPostProcessors.user("testuser")))
            .andExpect(status().isOk());
        
        // Wait for session to expire
        Thread.sleep(2000);
        
        // Try to access with expired session - should get 401
        session.invalidate();
        mockMvc.perform(get("/api/health").session(session))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void testApi_InvalidatedSession_Returns401() throws Exception {
        // Create and immediately invalidate session
        MockHttpSession session = new MockHttpSession();
        session.invalidate();
        
        // Should return 401
        mockMvc.perform(get("/api/user").session(session))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    @WithMockUser
    void testApi_ValidAuthentication_Returns200() throws Exception {
        mockMvc.perform(get("/api/health"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("UP"));
    }
    
    @Test
    void testApi_WithExpiredOidcToken_Returns401() throws Exception {
        // Create an OIDC token that's already expired
        Instant now = Instant.now();
        Instant issuedAt = now.minusSeconds(3600); // 1 hour ago
        Instant expiresAt = now.minusSeconds(1800); // 30 minutes ago (expired)
        
        Map<String, Object> claims = Map.of(
            "sub", "12345",
            "preferred_username", "john.doe@example.com",
            "email", "john.doe@example.com",
            "name", "John Doe"
        );
        
        OidcIdToken expiredIdToken = new OidcIdToken(
            "expired-token-value",
            issuedAt,
            expiresAt, // Expired
            claims
        );
        
        DefaultOidcUser oidcUser = new DefaultOidcUser(
            List.of(new SimpleGrantedAuthority("ROLE_USER")),
            expiredIdToken,
            "preferred_username"
        );
        
        OAuth2AuthenticationToken expiredAuth = new OAuth2AuthenticationToken(
            oidcUser,
            oidcUser.getAuthorities(),
            "oidc-0"
        );
        
        // Attempt to access API with expired token
        mockMvc.perform(get("/api/user")
                .with(authentication(expiredAuth)))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void testApi_WithValidOidcToken_Returns200() throws Exception {
        // Create a valid OIDC token
        Instant now = Instant.now();
        Instant issuedAt = now.minusSeconds(300); // 5 minutes ago
        Instant expiresAt = now.plusSeconds(3300); // 55 minutes from now
        
        Map<String, Object> claims = Map.of(
            "sub", "12345",
            "preferred_username", "john.doe@example.com",
            "email", "john.doe@example.com",
            "name", "John Doe"
        );
        
        OidcIdToken validIdToken = new OidcIdToken(
            "valid-token-value",
            issuedAt,
            expiresAt,
            claims
        );
        
        DefaultOidcUser oidcUser = new DefaultOidcUser(
            List.of(new SimpleGrantedAuthority("ROLE_USER")),
            validIdToken,
            "preferred_username"
        );
        
        OAuth2AuthenticationToken validAuth = new OAuth2AuthenticationToken(
            oidcUser,
            oidcUser.getAuthorities(),
            "oidc-0"
        );
        
        // Should be able to access API with valid token
        mockMvc.perform(get("/api/user")
                .with(authentication(validAuth)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("john.doe@example.com"));
    }
    
    @Test
    void testWebEndpoint_NoAuthentication_RedirectsToLogin() throws Exception {
        // Web endpoints should redirect to login, not return 401
        mockMvc.perform(get("/home"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"));
    }
    
    @Test
    void testApi_MultipleRequests_ConsistentBehavior() throws Exception {
        // Test multiple API endpoints to ensure consistent 401 behavior
        String[] apiEndpoints = {"/api/user", "/api/user-v2", "/api/health", "/api/test", "/api/data/123"};
        
        for (String endpoint : apiEndpoints) {
            mockMvc.perform(get(endpoint))
                .andExpect(status().isUnauthorized());
        }
    }
    
    @Test
    void testApi_PostRequest_NoAuth_Returns401() throws Exception {
        // Test POST requests also return 401
        mockMvc.perform(post("/api/data")
                .contentType("application/json")
                .content("{}"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void testApi_WithCsrfToken_StillRequiresAuth() throws Exception {
        // Even with CSRF token, should still require authentication
        mockMvc.perform(post("/api/data")
                .with(csrf())
                .contentType("application/json")
                .content("{}"))
            .andExpect(status().isUnauthorized());
    }
}