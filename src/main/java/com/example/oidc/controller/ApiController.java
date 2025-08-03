package com.example.oidc.controller;

import com.example.oidc.annotation.Username;
import com.example.oidc.security.SecurityContextHelper;
import com.example.oidc.util.RequestTrackingUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api")
public class ApiController {
    
    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getCurrentUser(@AuthenticationPrincipal OidcUser principal) {
        log.info("{}Getting current user info for: {}", 
                RequestTrackingUtil.getLogPrefix(), principal.getPreferredUsername());
        
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", principal.getPreferredUsername());
        userInfo.put("email", principal.getEmail());
        userInfo.put("name", principal.getFullName());
        userInfo.put("authenticated", true);
        
        // Include tracking IDs in response for debugging/tracing
        userInfo.put("correlationId", RequestTrackingUtil.getCorrelationId());
        userInfo.put("transactionId", RequestTrackingUtil.getTransactionId());
        
        return ResponseEntity.ok(userInfo);
    }
    
    @GetMapping("/user-v2")
    public ResponseEntity<Map<String, Object>> getCurrentUserV2(@Username String username, 
                                                                @Username(truncated = false) String fullUsername) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", username);
        userInfo.put("fullUsername", fullUsername);
        userInfo.put("email", SecurityContextHelper.getEmail());
        userInfo.put("name", SecurityContextHelper.getFullName());
        userInfo.put("roles", SecurityContextHelper.getRoles());
        userInfo.put("authType", SecurityContextHelper.getAuthenticationType());
        userInfo.put("tenantId", SecurityContextHelper.getTenantId());
        userInfo.put("authenticated", SecurityContextHelper.isAuthenticated());
        
        return ResponseEntity.ok(userInfo);
    }
    
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        log.debug("Health check endpoint called");
        
        Map<String, String> health = new HashMap<>();
        health.put("status", "UP");
        health.put("service", "oidc-multi-secret-demo");
        health.put("correlationId", RequestTrackingUtil.getCorrelationId());
        health.put("transactionId", RequestTrackingUtil.getTransactionId());
        
        return ResponseEntity.ok(health);
    }
}