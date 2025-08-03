# Security Configuration Guide

This document explains the security configurations implemented in this Spring Boot OIDC application.

## CORS Configuration

### Programmatic Configuration (SecurityConfig.java)

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:4200"));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(Arrays.asList("*"));
    configuration.setAllowCredentials(true);
    configuration.setExposedHeaders(Arrays.asList("Authorization", "X-Total-Count"));
    configuration.setMaxAge(Duration.ofHours(1));
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

### Key CORS Settings:
- **Allowed Origins**: Configure your frontend URLs (React, Angular, etc.)
- **Allowed Methods**: HTTP methods your API supports
- **Allow Credentials**: Required for cookie-based authentication
- **Exposed Headers**: Headers that the browser is allowed to access
- **Max Age**: How long the browser can cache CORS preflight responses

## CSRF Configuration

### Cookie-Based CSRF Protection

```java
CookieCsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
csrfTokenRepository.setCookieName("XSRF-TOKEN");
csrfTokenRepository.setHeaderName("X-XSRF-TOKEN");
```

### CSRF Settings:
- **Cookie Name**: `XSRF-TOKEN` (standard Angular convention)
- **Header Name**: `X-XSRF-TOKEN` (what frontend sends back)
- **HttpOnly**: Set to `false` so JavaScript can read the token
- **API Endpoints**: CSRF disabled for `/api/**` endpoints

### Frontend Integration:
```javascript
// Example: Reading CSRF token in JavaScript
const token = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN='))
    ?.split('=')[1];

// Include in requests
fetch('/api/data', {
    headers: {
        'X-XSRF-TOKEN': token
    }
});
```

## Session Configuration

### Session Expiry Behavior
- **API Endpoints (`/api/**`)**: Return `401 Unauthorized` when session expires
- **Web Endpoints**: Redirect to `/login` when session expires
- No redirect loops for REST API calls
- Clean error responses for frontend applications

### 1. Application Properties (application.yml)

```yaml
spring:
  session:
    timeout: 30m  # Server-side session timeout

server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: false  # Set to true in production
        same-site: lax
        max-age: 30m
```

### 2. Programmatic Configuration (SessionConfig.java)

```java
@Bean
public ServletContextInitializer servletContextInitializer() {
    return servletContext -> {
        SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
        sessionCookieConfig.setName("JSESSIONID");
        sessionCookieConfig.setHttpOnly(true);
        sessionCookieConfig.setSecure(false); // true in production
        sessionCookieConfig.setPath("/");
        sessionCookieConfig.setMaxAge(1800); // 30 minutes
    };
}
```

### 3. Security Config Session Management

```java
.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    .invalidSessionUrl("/login")
    .sessionFixation(fixation -> fixation.migrateSession())
    .maximumSessions(1)
        .maxSessionsPreventsLogin(false)
        .expiredUrl("/login")
        .sessionRegistry(sessionRegistry())
)
```

## Cookie Security Features

### Session Cookies:
- **HttpOnly**: Prevents JavaScript access (XSS protection)
- **Secure**: Only sent over HTTPS (enable in production)
- **SameSite=Lax**: CSRF protection
- **Path=/**: Available to entire application
- **Max-Age**: 30 minutes

### Logout Behavior:
```java
.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessUrl("/")
    .invalidateHttpSession(true)
    .deleteCookies("JSESSIONID", "SESSION", "XSRF-TOKEN")
    .clearAuthentication(true)
    .addLogoutHandler((request, response, authentication) -> {
        // Custom handler to clear all cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                cookie.setValue("");
                cookie.setPath("/");
                cookie.setMaxAge(0);
                response.addCookie(cookie);
            }
        }
    })
)
```

## API vs Web Security

### API Endpoints (/api/**)
- Return 401 Unauthorized (no redirect)
- CSRF protection disabled
- Suitable for REST clients

### Web Endpoints
- Redirect to login page when unauthorized
- CSRF protection enabled
- Session-based authentication

## Production Checklist

1. **Enable HTTPS**:
   - Set `cookie.secure=true` in application.yml
   - Set `useSecureCookie(true)` in code

2. **Update CORS Origins**:
   - Replace localhost with production domains
   - Remove development ports

3. **Strengthen Session Security**:
   - Consider shorter session timeouts
   - Enable concurrent session control if needed

4. **CSRF Token**:
   - Ensure frontend properly handles CSRF tokens
   - Consider using double-submit cookie pattern

5. **Cookie Domain**:
   - Set appropriate domain for cookies if using subdomains

## Example: Secure Production Configuration

```yaml
server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: true  # HTTPS only
        same-site: strict  # Stricter CSRF protection
        domain: .yourdomain.com  # For subdomain sharing
        max-age: 15m  # Shorter timeout
```

## Testing Security Features

### Test CORS:
```bash
# Preflight request
curl -X OPTIONS http://localhost:8080/api/user \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: GET"
```

### Test API 401:
```bash
# Should return 401, not redirect
curl -i http://localhost:8080/api/user
```

### Test CSRF:
```bash
# Get CSRF token
curl -c cookies.txt http://localhost:8080/

# Use token in request
curl -b cookies.txt -H "X-XSRF-TOKEN: <token-value>" \
  -X POST http://localhost:8080/some-endpoint
```