package com.example.oidc.controller;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.example.oidc.config.SpaProperties;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * Controller that handles SPA routing by serving index.html for client-side routes.
 * Dynamically registers the not-found route based on configuration.
 */
@Slf4j
@Controller
@ConditionalOnProperty(name = "spa.enabled", havingValue = "true", matchIfMissing = false)
public class SpaRoutingController {
    
    private final SpaProperties spaProperties;
    private final ApplicationContext applicationContext;
    private String cachedIndexHtml;
    private final Pattern notFoundUrlPattern = Pattern.compile("^([^?]+)(\\?.*)?$");
    
    public SpaRoutingController(SpaProperties spaProperties, ApplicationContext applicationContext) {
        this.spaProperties = spaProperties;
        this.applicationContext = applicationContext;
    }
    
    @PostConstruct
    public void registerDynamicRoute() {
        String notFoundUrl = spaProperties.getNotFoundUrl();
        if (notFoundUrl == null || notFoundUrl.isEmpty()) {
            return;
        }
        
        // Extract the path from the not-found URL (before query parameters)
        String notFoundPath = extractPath(notFoundUrl);
        if (notFoundPath == null || notFoundPath.isEmpty()) {
            return;
        }
        
        log.info("Registering dynamic SPA route for path: {}", notFoundPath);
        
        try {
            // Get the RequestMappingHandlerMapping bean
            RequestMappingHandlerMapping handlerMapping = applicationContext.getBean(RequestMappingHandlerMapping.class);
            
            // Get the method to register
            Method method = SpaRoutingController.class.getDeclaredMethod("handleNotFound", String.class, HttpServletRequest.class);
            
            // Create RequestMappingInfo
            RequestMappingInfo mappingInfo = RequestMappingInfo
                .paths(notFoundPath)
                .methods(org.springframework.web.bind.annotation.RequestMethod.GET)
                .produces(MediaType.TEXT_HTML_VALUE)
                .build();
            
            // Register the mapping
            handlerMapping.registerMapping(mappingInfo, this, method);
            
            log.info("Successfully registered dynamic route: {} -> handleNotFound", notFoundPath);
            
        } catch (Exception e) {
            log.error("Failed to register dynamic route for path: {}", notFoundPath, e);
        }
    }
    
    private String extractPath(String notFoundUrl) {
        if (notFoundUrl == null) {
            return null;
        }
        
        Matcher matcher = notFoundUrlPattern.matcher(notFoundUrl);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        return notFoundUrl;
    }
    
    /**
     * Handles the dynamically configured not-found route.
     * Serves the SPA index.html so Angular router can handle the route with query parameters.
     */
    @ResponseBody
    public String handleNotFound(
            @RequestParam(value = "page", required = false) String page,
            HttpServletRequest request) {
        
        log.debug("Handling {} route with page parameter: {}", request.getRequestURI(), page);
        
        // Return the index.html content
        // Angular router will read the URL including query params and route accordingly
        return getIndexHtmlContent();
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