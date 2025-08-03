package com.example.oidc.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configuration for Single Page Application (SPA) support.
 * Enables client-side routing by serving index.html for unmatched routes.
 */
@Slf4j
@Configuration
@ConditionalOnProperty(name = "spa.enabled", havingValue = "true", matchIfMissing = false)
@EnableConfigurationProperties(SpaProperties.class)
public class SpaConfiguration implements WebMvcConfigurer {
    
    private final SpaProperties spaProperties;
    
    public SpaConfiguration(SpaProperties spaProperties) {
        this.spaProperties = spaProperties;
        log.info("SPA Configuration enabled with properties: {}", spaProperties);
    }
    
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // Ensure static resources are served with proper cache headers
        registry.addResourceHandler("/**")
                .addResourceLocations("classpath:/static/", "classpath:/public/")
                .setCachePeriod(3600)
                .resourceChain(true);
    }
    
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // Add explicit mapping for root to index.html
        if ("/".equals(spaProperties.getIndexUrl()) || "index.html".equals(spaProperties.getIndexUrl())) {
            registry.addViewController("/").setViewName("forward:/" + spaProperties.getIndexUrl());
        }
    }
}