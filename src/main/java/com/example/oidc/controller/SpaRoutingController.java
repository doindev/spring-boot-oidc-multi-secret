package com.example.oidc.controller;

import com.example.oidc.config.SpaProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Controller that handles SPA routing by serving index.html for client-side routes.
 * This allows Angular router to handle routes like /not-found with query parameters.
 */
@Slf4j
@Controller
@ConditionalOnProperty(name = "spa.enabled", havingValue = "true", matchIfMissing = false)
public class SpaRoutingController {
    
    private final SpaProperties spaProperties;
    private String cachedIndexHtml;
    
    public SpaRoutingController(SpaProperties spaProperties) {
        this.spaProperties = spaProperties;
    }
    
    /**
     * Handles the /not-found route explicitly.
     * Serves the SPA index.html so Angular router can handle the route with query parameters.
     */
    @GetMapping(value = "/not-found", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String handleNotFound(
            @RequestParam(value = "page", required = false) String page,
            HttpServletRequest request) {
        
        log.debug("Handling /not-found route with page parameter: {}", page);
        
        // Return the index.html content
        // Angular router will read the URL including query params and route accordingly
        return getIndexHtmlContent();
    }
    
    /**
     * Catch-all mapping for SPA routes.
     * This ensures that deep links work by serving index.html for any unmatched routes.
     * Should be configured with lowest precedence.
     */
    @GetMapping(value = {
        "/{path:[^\\.]*}",
        "/**/{path:[^\\.]*}"
    }, produces = MediaType.TEXT_HTML_VALUE)
    @ResponseBody
    public String handleSpaRoute(HttpServletRequest request) {
        String path = request.getRequestURI();
        
        // Check if this is an API or static resource request that shouldn't be handled
        if (shouldExcludePath(path)) {
            // Return null to let Spring handle this as a 404
            return null;
        }
        
        log.debug("Serving index.html for SPA route: {}", path);
        
        // Check if we should redirect to the not-found route
        if (spaProperties.getNotFoundUrl() != null && 
            !spaProperties.getNotFoundUrl().isEmpty() &&
            !path.equals("/") &&
            !path.startsWith("/not-found")) {
            
            // For unknown routes, we could optionally redirect to Angular's not-found route
            // But typically we just serve index.html and let Angular handle it
            String encodedPath = URLEncoder.encode(path, StandardCharsets.UTF_8);
            String redirectUrl = spaProperties.getNotFoundUrl()
                .replace("{notFoundUrl}", encodedPath);
            
            // Optional: Add a header to indicate this was a fallback route
            request.setAttribute("spa.fallback", true);
            request.setAttribute("spa.originalPath", path);
        }
        
        return getIndexHtmlContent();
    }
    
    private boolean shouldExcludePath(String path) {
        // Don't handle paths with file extensions (except .html)
        if (path.contains(".") && !path.endsWith(".html")) {
            return true;
        }
        
        // Don't handle API paths
        if (path.startsWith("/api/") || 
            path.startsWith("/actuator/") ||
            path.startsWith("/oauth2/") ||
            path.startsWith("/login")) {
            return true;
        }
        
        return false;
    }
    
    private String getIndexHtmlContent() {
        if (cachedIndexHtml == null) {
            try {
                String indexFileName = spaProperties.getIndexUrl();
                log.debug("Loading SPA index file: {}", indexFileName);
                
                // Try different locations for the index file
                Resource resource = new ClassPathResource("static/" + indexFileName);
                if (!resource.exists()) {
                    resource = new ClassPathResource("templates/" + indexFileName);
                }
                if (!resource.exists()) {
                    resource = new ClassPathResource("public/" + indexFileName);
                }
                if (!resource.exists()) {
                    resource = new ClassPathResource(indexFileName);
                }
                
                if (resource.exists()) {
                    cachedIndexHtml = StreamUtils.copyToString(
                        resource.getInputStream(), 
                        StandardCharsets.UTF_8
                    );
                    log.info("Successfully loaded SPA index file from: {}", resource.getURL());
                } else {
                    log.warn("SPA index file not found: {}. Tried locations: static/, templates/, public/, and classpath root", indexFileName);
                    cachedIndexHtml = getDefaultSpaHtml();
                }
            } catch (IOException e) {
                log.error("Failed to load SPA index file: {}", spaProperties.getIndexUrl(), e);
                cachedIndexHtml = getDefaultSpaHtml();
            }
        }
        return cachedIndexHtml;
    }
    
    private String getDefaultSpaHtml() {
        return """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Application</title>
                <base href="/">
                <script>
                    // Example: Log the current path for debugging
                    console.log('SPA loaded for path:', window.location.pathname + window.location.search);
                </script>
            </head>
            <body>
                <div id="app">
                    <h1>Single Page Application</h1>
                    <p>Your Angular app should be loaded here.</p>
                    <p>Current path: <span id="current-path"></span></p>
                    <script>
                        document.getElementById('current-path').textContent = 
                            window.location.pathname + window.location.search;
                    </script>
                </div>
            </body>
            </html>
            """;
    }
}