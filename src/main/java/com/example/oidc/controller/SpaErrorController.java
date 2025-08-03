package com.example.oidc.controller;

import com.example.oidc.config.SpaProperties;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Error controller for Single Page Application (SPA) support.
 * Handles 404 errors by serving the SPA index page, allowing client-side routing to take over.
 */
@Slf4j
@Controller
@ConditionalOnProperty(name = "spa.enabled", havingValue = "true", matchIfMissing = false)
public class SpaErrorController implements ErrorController {
    
    private final SpaProperties spaProperties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private String cachedIndexHtml;
    
    public SpaErrorController(SpaProperties spaProperties) {
        this.spaProperties = spaProperties;
        log.info("SPA Error Controller initialized with index URL: {}", spaProperties.getIndexUrl());
    }
    
    @RequestMapping("${server.error.path:${error.path:/error}}")
    public Object handleError(HttpServletRequest request, HttpServletResponse response) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        
        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());
            
            // Only handle 404 errors for SPA routing
            if (statusCode == HttpStatus.NOT_FOUND.value()) {
                String originalPath = getOriginalPath(request);
                
                // Check if this path should be excluded from SPA handling
                if (shouldExcludePath(originalPath)) {
                    log.debug("Path {} is excluded from SPA handling, returning regular 404", originalPath);
                    return handleRegular404(response);
                }
                
                log.debug("Handling 404 for path: {} with SPA routing", originalPath);
                
                // Always serve the index.html content for 404s
                // The Angular router will handle the actual routing based on the URL
                response.setStatus(HttpStatus.OK.value());
                response.setContentType(MediaType.TEXT_HTML_VALUE);
                try {
                    response.getWriter().write(getIndexHtmlContent());
                    response.getWriter().flush();
                    return null;
                } catch (IOException e) {
                    log.error("Failed to write index.html content", e);
                    return handleRegular404(response);
                }
            }
        }
        
        // For non-404 errors, return a simple error response
        return handleRegularError(request, response);
    }
    
    
    private String getOriginalPath(HttpServletRequest request) {
        String path = (String) request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        if (path == null) {
            path = request.getRequestURI();
        }
        return path;
    }
    
    private boolean shouldExcludePath(String path) {
        if (spaProperties.getExcludePatterns() != null) {
            for (String pattern : spaProperties.getExcludePatterns()) {
                if (pathMatcher.match(pattern, path)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    
    private String getIndexHtmlContent() {
        // Cache the index file content for performance
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
                    log.info("Successfully cached SPA index file from: {}", resource.getURL());
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
            </head>
            <body>
                <div id="root">
                    <h1>Single Page Application</h1>
                    <p>Configure your SPA index file location in application properties.</p>
                </div>
            </body>
            </html>
            """;
    }
    
    private ModelAndView handleRegular404(HttpServletResponse response) {
        response.setStatus(HttpStatus.NOT_FOUND.value());
        // Return empty ModelAndView to generate a simple 404 response
        return new ModelAndView();
    }
    
    private ModelAndView handleRegularError(HttpServletRequest request, HttpServletResponse response) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        int statusCode = status != null ? Integer.parseInt(status.toString()) : 500;
        
        response.setStatus(statusCode);
        ModelAndView mav = new ModelAndView("error");
        mav.addObject("status", statusCode);
        mav.addObject("error", HttpStatus.valueOf(statusCode).getReasonPhrase());
        mav.addObject("message", request.getAttribute(RequestDispatcher.ERROR_MESSAGE));
        return mav;
    }
}