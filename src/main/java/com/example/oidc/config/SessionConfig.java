package com.example.oidc.config;

import org.springframework.boot.web.servlet.server.CookieSameSiteSupplier;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.servlet.SessionCookieConfig;
import jakarta.servlet.http.Cookie;

@Configuration
public class SessionConfig {
    
    /**
     * Programmatic session cookie configuration example.
     * This demonstrates how to configure session cookies programmatically
     * as an alternative or supplement to application.yml configuration.
     */
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
            
            // Cookie name
            sessionCookieConfig.setName("JSESSIONID");
            
            // HttpOnly - prevents JavaScript access
            sessionCookieConfig.setHttpOnly(true);
            
            // Secure - only send over HTTPS (set to true in production)
            sessionCookieConfig.setSecure(false);
            
            // Cookie path
            sessionCookieConfig.setPath("/");
            
            // Cookie max age (in seconds)
            sessionCookieConfig.setMaxAge(1800); // 30 minutes
            
            // Domain (null = current domain only)
            // sessionCookieConfig.setDomain(".example.com");
            
            // Note: SameSite must be set via application properties or CookieSameSiteSupplier
        };
    }
    
    /**
     * Alternative way to configure SameSite for all cookies
     */
    @Bean
    public CookieSameSiteSupplier cookieSameSiteSupplier() {
        return CookieSameSiteSupplier.ofLax();
    }
    
    /**
     * Example of a custom cookie configuration bean that could be used
     * for remember-me or other custom cookies
     */
    @Bean
    public CustomCookieConfig customCookieConfig() {
        return new CustomCookieConfig();
    }
    
    public static class CustomCookieConfig {
        
        public Cookie createSecureCookie(String name, String value) {
            Cookie cookie = new Cookie(name, value);
            cookie.setHttpOnly(true);
            cookie.setSecure(false); // Set to true in production
            cookie.setPath("/");
            cookie.setMaxAge(3600); // 1 hour
            cookie.setAttribute("SameSite", "Lax");
            return cookie;
        }
        
        public void deleteCookie(Cookie cookie) {
            cookie.setValue("");
            cookie.setPath("/");
            cookie.setMaxAge(0);
        }
    }
}