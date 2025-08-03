package com.example.oidc.controller;

import com.example.oidc.config.SpaProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for dynamic SPA routing with custom not-found URLs.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("spa-custom")
@TestPropertySource(properties = {
    "logging.level.com.example.oidc.controller=DEBUG"
})
class SpaDynamicRoutingTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private SpaProperties spaProperties;
    
    @Test
    void testCustomNotFoundUrlIsRegistered() throws Exception {
        // Verify the custom URL from application-spa-custom.yml is loaded
        assertThat(spaProperties.getNotFoundUrl()).isEqualTo("/page-not-found?original={notFoundUrl}");
        
        // Test that the custom /page-not-found route is registered and works
        MvcResult result = mockMvc.perform(get("/page-not-found")
                .queryParam("original", "/some/missing/page"))
            .andExpect(status().isOk())
            .andExpect(content().contentType("text/html;charset=UTF-8"))
            .andReturn();
        
        String content = result.getResponse().getContentAsString();
        assertThat(content).contains("Single Page Application");
    }
    
    @Test
    void testDynamicRouteWithDifferentQueryParam() throws Exception {
        // Test with different query parameter name
        MvcResult result = mockMvc.perform(get("/page-not-found")
                .queryParam("original", "/products/123")
                .queryParam("extra", "value"))
            .andExpect(status().isOk())
            .andExpect(content().contentType("text/html;charset=UTF-8"))
            .andReturn();
        
        String content = result.getResponse().getContentAsString();
        assertThat(content).contains("Single Page Application");
    }
    
    @Test
    void testDynamicRouteWithoutQueryParams() throws Exception {
        // Test the custom route without query parameters
        MvcResult result = mockMvc.perform(get("/page-not-found"))
            .andExpect(status().isOk())
            .andExpect(content().contentType("text/html;charset=UTF-8"))
            .andReturn();
        
        String content = result.getResponse().getContentAsString();
        assertThat(content).contains("Single Page Application");
    }
    
    @Test
    void testOriginalNotFoundRouteDoesNotExist() throws Exception {
        // The hardcoded /not-found route should not exist since we're using /page-not-found
        mockMvc.perform(get("/not-found"))
            .andExpect(status().isNotFound());
    }
}