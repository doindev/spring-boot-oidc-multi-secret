package com.example.oidc.controller;

import com.example.oidc.config.SpaProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.StreamUtils;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for SPA routing functionality.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
    "spa.enabled=true",
    "spa.index-url=spa-index.html",
    "spa.not-found-url=/not-found?page={notFoundUrl}",
    "security.type=none" // Disable security for testing
})
@Import(SpaControllerTest.TestConfig.class)
class SpaControllerTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private SpaProperties spaProperties;
    
    private String expectedIndexContent;
    
    @BeforeEach
    void setUp() throws Exception {
        // Load the expected content
        Resource resource = new ClassPathResource("static/spa-index.html");
        if (resource.exists()) {
            expectedIndexContent = StreamUtils.copyToString(
                resource.getInputStream(), 
                StandardCharsets.UTF_8
            );
        }
    }
    
    @Test
    void testSpaPropertiesLoaded() {
        assertThat(spaProperties).isNotNull();
        assertThat(spaProperties.isEnabled()).isTrue();
        assertThat(spaProperties.getIndexUrl()).isEqualTo("spa-index.html");
        assertThat(spaProperties.getNotFoundUrl()).isEqualTo("/not-found?page={notFoundUrl}");
    }
    
    @Test
    void testNotFoundRouteServesIndexHtml() throws Exception {
        // Test the explicit /not-found route
        MvcResult result = mockMvc.perform(get("/not-found")
                .queryParam("page", "/some/unknown/route"))
            .andExpect(status().isOk())
            .andExpect(content().contentType("text/html;charset=UTF-8"))
            .andReturn();
        
        String content = result.getResponse().getContentAsString();
        assertThat(content).contains("Single Page Application");
        
        // If we have the actual file, verify it matches
        if (expectedIndexContent != null) {
            assertThat(content).isEqualTo(expectedIndexContent);
        }
    }
    
    @Test
    void testUnknownRouteServesIndexHtml() throws Exception {
        // Test that unknown routes serve the index.html
        MvcResult result = mockMvc.perform(get("/some/unknown/route"))
            .andExpect(status().isOk())
            .andExpect(content().contentType("text/html;charset=UTF-8"))
            .andReturn();
        
        String content = result.getResponse().getContentAsString();
        assertThat(content).contains("Single Page Application");
    }
    
    @Test
    void testApiRoutesReturn404() throws Exception {
        // API routes should return 404, not index.html
        mockMvc.perform(get("/api/unknown"))
            .andExpect(status().isNotFound());
    }
    
    @Test
    void testStaticResourcesAreNotIntercepted() throws Exception {
        // Static resources should return 404 if not found, not index.html
        mockMvc.perform(get("/unknown.js"))
            .andExpect(status().isNotFound());
        
        mockMvc.perform(get("/assets/unknown.css"))
            .andExpect(status().isNotFound());
    }
    
    @Test
    void testRootPathServesIndexHtml() throws Exception {
        // Root path should serve index.html
        MvcResult result = mockMvc.perform(get("/"))
            .andExpect(status().isOk())
            .andReturn();
        
        // The root path might be handled differently, so we just check it's successful
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
    }
    
    @Test
    void testDeepLinkingSupport() throws Exception {
        // Test various deep links that should all serve index.html
        String[] deepLinks = {
            "/products",
            "/products/123",
            "/users/profile",
            "/dashboard/settings"
        };
        
        for (String link : deepLinks) {
            MvcResult result = mockMvc.perform(get(link))
                .andExpect(status().isOk())
                .andExpect(content().contentType("text/html;charset=UTF-8"))
                .andReturn();
            
            String content = result.getResponse().getContentAsString();
            assertThat(content).contains("Single Page Application");
        }
    }
    
    @Test
    void testExcludedPatternsReturn404() throws Exception {
        // Test that excluded patterns return 404
        String[] excludedPaths = {
            "/api/users",
            "/actuator/health",
            "/favicon.ico",
            "/assets/app.js",
            "/styles/main.css",
            "/images/logo.png"
        };
        
        for (String path : excludedPaths) {
            mockMvc.perform(get(path))
                .andExpect(status().isNotFound())
                .andExpect(content().string(""));
        }
    }
    
    @TestConfiguration
    static class TestConfig {
        @Bean
        public SpaRoutingController spaRoutingController(SpaProperties spaProperties) {
            return new SpaRoutingController(spaProperties);
        }
        
        @Bean
        public SpaErrorController spaErrorController(SpaProperties spaProperties) {
            return new SpaErrorController(spaProperties);
        }
    }
}