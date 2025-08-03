package com.example.oidc.config;

import com.example.oidc.controller.ApiController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SessionExpiryTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void testApiEndpoint_NoSession_Returns401() throws Exception {
        // Test API endpoint without session returns 401
        mockMvc.perform(get("/api/user"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void testWebEndpoint_NoSession_RedirectsToLogin() throws Exception {
        // Test web endpoint without session redirects to login
        mockMvc.perform(get("/home"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"));
    }
    
    @Test
    @WithMockUser
    void testApiEndpoint_WithValidSession_Returns200() throws Exception {
        // Test API endpoint with valid session returns data
        mockMvc.perform(get("/api/health"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("UP"));
    }
    
    @Test
    void testApiEndpoint_WithInvalidatedSession_Returns401() throws Exception {
        // Create a session
        MockHttpSession session = new MockHttpSession();
        
        // First request with session should be unauthorized (no auth)
        mockMvc.perform(get("/api/user").session(session))
            .andExpect(status().isUnauthorized());
        
        // Invalidate the session
        session.invalidate();
        
        // Request with invalidated session should return 401
        mockMvc.perform(get("/api/user").session(session))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void testWebEndpoint_WithInvalidatedSession_RedirectsToLogin() throws Exception {
        // Create a session
        MockHttpSession session = new MockHttpSession();
        
        // Invalidate the session
        session.invalidate();
        
        // Request with invalidated session should redirect to login
        mockMvc.perform(get("/home").session(session))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"));
    }
}