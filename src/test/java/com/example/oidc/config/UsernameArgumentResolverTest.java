package com.example.oidc.config;

import com.example.oidc.annotation.Username;
import com.example.oidc.controller.ApiController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.mockito.Mock;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = ApiController.class)
@Import({UsernameArgumentResolver.class, WebConfig.class})
@ActiveProfiles("webmvctest")
class UsernameArgumentResolverTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;
    
    @Test
    @WithMockUser(username = "john.doe@example.com")
    void testUsernameAnnotationWithTruncation() throws Exception {
        mockMvc.perform(get("/api/user-v2"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("john.doe"))
            .andExpect(jsonPath("$.fullUsername").value("john.doe@example.com"))
            .andExpect(jsonPath("$.authType").value("BASIC_AUTH"));
    }
    
    @Test
    @WithMockUser(username = "simpleuser")
    void testUsernameWithoutDomain() throws Exception {
        mockMvc.perform(get("/api/user-v2"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("simpleuser"))
            .andExpect(jsonPath("$.fullUsername").value("simpleuser"));
    }
    
    @Test
    void testUnauthenticatedRequest() throws Exception {
        // Should return 401 due to security configuration
        mockMvc.perform(get("/api/user-v2"))
            .andExpect(status().isUnauthorized());
    }
}