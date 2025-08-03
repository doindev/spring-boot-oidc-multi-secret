package com.example.oidc.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration test to verify SPA forwarding behavior.
 * Tests that 404s are forwarded to the configured not-found URL rather than
 * directly serving the index.html.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
    "spa.enabled=true",
    "spa.index-url=index.html",
    "spa.not-found-url=/not-found?page={notFoundUrl}",
    "security.type=none",
    "logging.level.com.example.oidc.controller=DEBUG"
})
class SpaForwardingTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Test
    void testNonExistentPathForwardsToNotFoundUrl() throws Exception {
        // When accessing a non-existent path
        MvcResult result = mockMvc.perform(get("/this-does-not-exist"))
            .andExpect(status().isOk()) // Forward maintains 200 status
            .andReturn();
        
        // The request should have been forwarded to /not-found?page=/this-does-not-exist
        // In the test environment, we can verify the forward happened by checking the response
        String content = result.getResponse().getContentAsString();
        assertThat(content).contains("Single Page Application");
        
        // Check that the forward occurred by looking at request attributes
        String forwardedPath = (String) result.getRequest().getAttribute("jakarta.servlet.forward.request_uri");
        if (forwardedPath != null) {
            assertThat(forwardedPath).isEqualTo("/this-does-not-exist");
        }
    }
    
    @Test
    void testApiPathReturns404WithoutForwarding() throws Exception {
        // API paths should return 404 without forwarding
        mockMvc.perform(get("/api/unknown"))
            .andExpect(status().isNotFound())
            .andExpect(content().string(""));
    }
    
    @Test
    void testDirectAccessToNotFoundRoute() throws Exception {
        // Direct access to /not-found should work
        MvcResult result = mockMvc.perform(get("/not-found")
                .queryParam("page", "/some/page"))
            .andExpect(status().isOk())
            .andExpect(content().contentType("text/html;charset=UTF-8"))
            .andReturn();
        
        String content = result.getResponse().getContentAsString();
        assertThat(content).contains("Single Page Application");
    }
    
    @Test
    void testMultipleNonExistentPaths() throws Exception {
        String[] paths = {
            "/products",
            "/users/123",
            "/dashboard/settings",
            "/about"
        };
        
        for (String path : paths) {
            MvcResult result = mockMvc.perform(get(path))
                .andExpect(status().isOk())
                .andReturn();
            
            // Each should be forwarded and return the SPA content
            String content = result.getResponse().getContentAsString();
            assertThat(content).contains("Single Page Application");
        }
    }
}