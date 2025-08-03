package com.example.oidc.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for Single Page Application (SPA) support.
 * Enables automatic routing of 404 errors to a not-found handler that serves the SPA index page.
 */
@Data
@Component
@ConfigurationProperties(prefix = "spa")
public class SpaProperties {
    
    /**
     * Enable SPA mode. When enabled, 404 errors will be handled by serving the SPA index page.
     */
    private boolean enabled = true;
    
    /**
     * The URL path to the SPA index file (relative to static resources).
     * Default: "index.html"
     */
    private String indexUrl = "index.html";
    
    /**
     * The URL pattern for handling not found (404) errors.
     * Supports placeholder {notFoundUrl} which will be replaced with the original requested URL.
     * Default: "/not-found?page={notFoundUrl}"
     */
    private String notFoundUrl = "/not-found?page={notFoundUrl}";
    
    /**
     * Whether to forward API requests (typically /api/**) to the not-found handler.
     * Usually you want this to be false to return proper 404 for API endpoints.
     */
    private boolean forwardApiRequests = false;
    
    /**
     * Path patterns to exclude from SPA routing (will return normal 404).
     * Useful for static assets like images, CSS, JS files.
     */
    private String[] excludePatterns = {
        "/api/**",
        "/actuator/**",
        "/favicon.ico",
        "/**/*.js",
        "/**/*.css",
        "/**/*.png",
        "/**/*.jpg",
        "/**/*.jpeg",
        "/**/*.gif",
        "/**/*.svg",
        "/**/*.woff",
        "/**/*.woff2",
        "/**/*.ttf",
        "/**/*.eot"
    };
}