# @Username Annotation and SecurityContextHelper Guide

## Overview

This guide explains how to use the custom `@Username` annotation and the `SecurityContextHelper` utility class for handling authentication across different providers (OIDC, JWT, Basic Auth, Microsoft Entra ID).

## @Username Annotation

### Basic Usage

```java
@GetMapping("/profile")
public String getProfile(@Username String username) {
    // username is automatically populated from security context
    return "Hello, " + username;
}
```

### With Truncation Control

```java
@GetMapping("/details")
public Map<String, String> getDetails(
    @Username String shortName,                          // Default: truncated (user)
    @Username(truncated = false) String fullUsername) {  // Full username (user@domain.com)
    
    return Map.of(
        "short", shortName,
        "full", fullUsername
    );
}
```

### Combined with Other Annotations

```java
@GetMapping("/mixed")
public String mixed(@Username String username,
                   @AuthenticationPrincipal OidcUser principal,
                   @RequestParam String param) {
    // Mix @Username with other Spring annotations
    return username + " - " + principal.getEmail();
}
```

## SecurityContextHelper Usage

### Get Username

```java
// Get truncated username (default)
String username = SecurityContextHelper.getUsername(true);  // "john"

// Get full username
String fullUsername = SecurityContextHelper.getUsername(false);  // "john@example.com"
```

### Get User Information

```java
// Get email
String email = SecurityContextHelper.getEmail();

// Get full name
String fullName = SecurityContextHelper.getFullName();

// Check authentication status
boolean isAuthenticated = SecurityContextHelper.isAuthenticated();

// Get authentication type
String authType = SecurityContextHelper.getAuthenticationType(); // "OIDC", "JWT", "BASIC_AUTH"
```

### Get Claims

```java
// Get specific claim
Object claimValue = SecurityContextHelper.getClaim("department");

// Get all claims
Map<String, Object> allClaims = SecurityContextHelper.getAllClaims();

// Get tenant ID (for multi-tenant scenarios)
String tenantId = SecurityContextHelper.getTenantId();
```

### Work with Roles

```java
// Get all roles
Set<String> roles = SecurityContextHelper.getRoles();

// Check specific role
boolean isAdmin = SecurityContextHelper.hasRole("ADMIN");       // Checks for ROLE_ADMIN
boolean isUser = SecurityContextHelper.hasRole("ROLE_USER");   // Also works with prefix
```

## Examples by Authentication Type

### OIDC Authentication

```java
@RestController
public class OidcController {
    
    @GetMapping("/oidc/info")
    public Map<String, Object> getOidcInfo(@Username String username) {
        return Map.of(
            "username", username,
            "email", SecurityContextHelper.getEmail(),
            "fullName", SecurityContextHelper.getFullName(),
            "authType", SecurityContextHelper.getAuthenticationType(),
            "claims", SecurityContextHelper.getAllClaims()
        );
    }
}
```

### JWT Authentication

```java
@RestController
public class JwtController {
    
    @GetMapping("/jwt/claims")
    public Map<String, Object> getJwtClaims(@Username String username) {
        return Map.of(
            "username", username,
            "subject", SecurityContextHelper.getClaim("sub"),
            "issuer", SecurityContextHelper.getClaim("iss"),
            "audience", SecurityContextHelper.getClaim("aud"),
            "roles", SecurityContextHelper.getRoles()
        );
    }
}
```

### Microsoft Entra ID (Azure AD)

```java
@RestController
public class EntraController {
    
    @GetMapping("/entra/tenant")
    public Map<String, Object> getTenantInfo(@Username String username) {
        return Map.of(
            "username", username,
            "tenantId", SecurityContextHelper.getTenantId(),
            "upn", SecurityContextHelper.getClaim("upn"),
            "groups", SecurityContextHelper.getClaim("groups"),
            "authType", SecurityContextHelper.getAuthenticationType()
        );
    }
}
```

### Basic Authentication

```java
@RestController
public class BasicAuthController {
    
    @GetMapping("/basic/user")
    public Map<String, Object> getBasicAuthUser(@Username String username) {
        return Map.of(
            "username", username,
            "roles", SecurityContextHelper.getRoles(),
            "authType", SecurityContextHelper.getAuthenticationType()
        );
    }
}
```

## Service Layer Usage

```java
@Service
public class UserService {
    
    public UserProfile getCurrentUserProfile() {
        String username = SecurityContextHelper.getUsername(true);
        String email = SecurityContextHelper.getEmail();
        Set<String> roles = SecurityContextHelper.getRoles();
        
        return UserProfile.builder()
            .username(username)
            .email(email)
            .roles(roles)
            .build();
    }
    
    public boolean canAccessResource(String resourceId) {
        // Check roles
        if (SecurityContextHelper.hasRole("ADMIN")) {
            return true;
        }
        
        // Check tenant for multi-tenant scenarios
        String tenantId = SecurityContextHelper.getTenantId();
        return resourceBelongsToTenant(resourceId, tenantId);
    }
}
```

## Testing

### Unit Testing with @Username

```java
@WebMvcTest(UserController.class)
class UserControllerTest {
    
    @Test
    @WithMockUser(username = "testuser@example.com")
    void testUsernameAnnotation() throws Exception {
        mockMvc.perform(get("/user/profile"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("testuser")));
    }
}
```

### Mocking SecurityContextHelper

```java
@Test
void testSecurityContextHelper() {
    // Set up security context
    Authentication auth = new UsernamePasswordAuthenticationToken(
        "user@example.com", null, 
        List.of(new SimpleGrantedAuthority("ROLE_USER"))
    );
    SecurityContextHolder.getContext().setAuthentication(auth);
    
    // Test
    assertEquals("user", SecurityContextHelper.getUsername(true));
    assertEquals("user@example.com", SecurityContextHelper.getUsername(false));
    assertTrue(SecurityContextHelper.hasRole("USER"));
}
```

## Configuration Notes

1. **Argument Resolver**: The `UsernameArgumentResolver` is automatically registered via `WebConfig`
2. **Security Context**: Uses Spring Security's `SecurityContextHolder`
3. **Thread Safety**: All methods are thread-safe as they use thread-local security context
4. **Null Safety**: Methods return `null` when no authentication is present

## Common Use Cases

### 1. Audit Logging
```java
@Aspect
@Component
public class AuditAspect {
    
    @Before("@annotation(Audited)")
    public void audit(JoinPoint joinPoint) {
        String username = SecurityContextHelper.getUsername(true);
        String action = joinPoint.getSignature().getName();
        log.info("User {} performed action {}", username, action);
    }
}
```

### 2. Multi-Tenant Data Filtering
```java
@Repository
public class TenantAwareRepository {
    
    public List<Entity> findAll() {
        String tenantId = SecurityContextHelper.getTenantId();
        return entityManager.createQuery(
            "SELECT e FROM Entity e WHERE e.tenantId = :tenantId", Entity.class)
            .setParameter("tenantId", tenantId)
            .getResultList();
    }
}
```

### 3. Dynamic Authorization
```java
@PreAuthorize("@securityService.canAccess(#id)")
@GetMapping("/resource/{id}")
public Resource getResource(@PathVariable Long id) {
    return resourceService.findById(id);
}

@Component("securityService")
public class SecurityService {
    public boolean canAccess(Long resourceId) {
        return SecurityContextHelper.hasRole("ADMIN") || 
               isResourceOwner(resourceId, SecurityContextHelper.getUsername(false));
    }
}
```

## Best Practices

1. **Use @Username for Controllers**: Prefer `@Username` annotation in controllers for cleaner code
2. **Use Helper for Services**: Use `SecurityContextHelper` in service/component layers
3. **Null Checks**: Always check for null when authentication might not be present
4. **Truncation**: Use truncated usernames for display, full usernames for lookups
5. **Caching**: Consider caching expensive operations like role checks in request scope

## Troubleshooting

### Username is null
- Ensure user is authenticated
- Check security configuration allows the endpoint
- Verify authentication type is supported

### Wrong username format
- Check the `truncated` parameter
- Verify the authentication provider sets the expected claims
- Check claim names for your specific provider

### Claims not found
- Use `getAllClaims()` to see available claims
- Check token/authentication configuration
- Verify claim names match your provider's format