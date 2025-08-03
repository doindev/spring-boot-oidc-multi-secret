package com.example.oidc.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller to display current security configuration and authentication info.
 */
@RestController
public class SecurityInfoController {
    
    @Value("${security.type:not-configured}")
    private String securityType;
    
    @GetMapping("/security-info")
    public Map<String, Object> getSecurityInfo() {
        Map<String, Object> info = new HashMap<>();
        
        // Security type
        info.put("securityType", securityType);
        
        // Authentication info
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            info.put("authenticated", auth.isAuthenticated());
            info.put("principal", auth.getName());
            info.put("authorities", auth.getAuthorities());
            info.put("authenticationType", auth.getClass().getSimpleName());
        } else {
            info.put("authenticated", false);
            info.put("principal", "anonymous");
        }
        
        return info;
    }
}