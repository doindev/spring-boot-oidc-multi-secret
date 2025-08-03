# OIDC Logout Configuration Guide

This guide explains the OIDC logout implementation in this Spring Boot application.

## Overview

OIDC logout ensures that users are logged out from both the application and the OIDC provider (Single Logout). There are two main types:

1. **RP-Initiated Logout** - The application initiates logout at the OIDC provider
2. **Back-Channel Logout** - The OIDC provider notifies the application of logout

## Configuration

### 1. Basic OIDC Logout (SecurityConfig.java)

```java
.oidcLogout(oidc -> oidc
    .backChannel(backChannel -> backChannel
        .logoutUri("/logout/connect/back-channel/{registrationId}")
    )
)
```

This configures the endpoint where the OIDC provider can send back-channel logout notifications.

### 2. Custom OIDC Logout Handler (OidcLogoutSuccessHandler.java)

The `OidcLogoutSuccessHandler` implements RP-Initiated Logout:

```java
.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessHandler(oidcLogoutSuccessHandler)  // Enable this for RP-initiated logout
    .invalidateHttpSession(true)
    .deleteCookies("JSESSIONID", "SESSION", "XSRF-TOKEN")
    .clearAuthentication(true)
)
```

### 3. Application Properties (application.yml)

```yaml
app:
  oidc:
    # Standard OIDC endpoints
    issuer-uri: https://your-oidc-provider.com
    authorization-uri: ${app.oidc.issuer-uri}/protocol/openid-connect/auth
    token-uri: ${app.oidc.issuer-uri}/protocol/openid-connect/token
    user-info-uri: ${app.oidc.issuer-uri}/protocol/openid-connect/userinfo
    jwk-set-uri: ${app.oidc.issuer-uri}/protocol/openid-connect/certs
    
    # Logout specific endpoints
    end-session-uri: ${app.oidc.issuer-uri}/protocol/openid-connect/logout
    post-logout-redirect-uri: http://localhost:8080
```

## How It Works

### RP-Initiated Logout Flow

1. User clicks logout in the application
2. Application clears local session and cookies
3. `OidcLogoutSuccessHandler` redirects to OIDC provider's `end_session_endpoint`
4. OIDC provider clears its session
5. OIDC provider redirects back to `post_logout_redirect_uri`

### Back-Channel Logout Flow

1. User logs out at the OIDC provider (or another application)
2. OIDC provider sends a logout token to `/logout/connect/back-channel/{registrationId}`
3. Application validates the logout token
4. Application terminates the user's session

## Provider-Specific Configuration

### Keycloak
```yaml
end-session-uri: ${issuer-uri}/protocol/openid-connect/logout
```

### Auth0
```yaml
end-session-uri: ${issuer-uri}/v2/logout
```

### Okta
```yaml
end-session-uri: ${issuer-uri}/v1/logout
```

### Microsoft Entra ID (Azure AD)
```yaml
end-session-uri: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout
```

## Implementation Details

### OidcLogoutSuccessHandler Features

1. **Automatic Provider Detection**: Detects common OIDC providers and their logout endpoints
2. **ID Token Hint**: Includes the ID token for secure logout
3. **Post-Logout Redirect**: Configurable redirect after logout
4. **Client ID**: Includes client ID when required by the provider

### Logout URL Parameters

The handler constructs a logout URL with these parameters:
- `id_token_hint` - The user's ID token (for security)
- `post_logout_redirect_uri` - Where to redirect after logout
- `client_id` - The application's client ID

Example logout URL:
```
https://provider.com/logout?
  id_token_hint=eyJhbGc...
  &post_logout_redirect_uri=http://localhost:8080
  &client_id=my-app
```

## Usage

### Enable Full OIDC Logout

To enable RP-initiated logout, uncomment the logout success handler in SecurityConfig:

```java
.logout(logout -> logout
    .logoutUrl("/logout")
    .logoutSuccessHandler(oidcLogoutSuccessHandler)  // Uncomment this line
    // ... rest of configuration
)
```

### Testing Logout

1. **Local Logout Only** (current configuration):
   - Navigate to `/logout`
   - Only application session is cleared
   - User remains logged in at OIDC provider

2. **Full OIDC Logout** (with handler enabled):
   - Navigate to `/logout`
   - Application session is cleared
   - Redirected to OIDC provider logout
   - OIDC provider session is cleared
   - Redirected back to application

### Custom Post-Logout Behavior

To customize post-logout behavior, modify the `OidcLogoutSuccessHandler`:

```java
// Add custom logic in onLogoutSuccess method
if (someCondition) {
    targetUrl = "/custom-logout-page";
}
```

## Security Considerations

1. **ID Token Storage**: The ID token is needed for logout. Spring Security stores it securely.
2. **CSRF Protection**: Logout endpoint is protected by CSRF token
3. **Cookie Cleanup**: All session cookies are cleared on logout
4. **Redirect Validation**: Only configured URIs are allowed for post-logout redirect

## Troubleshooting

### Logout Not Working with OIDC Provider

1. Check if `end_session_endpoint` is correctly configured
2. Verify `post_logout_redirect_uri` is registered with the provider
3. Check browser console for redirect errors
4. Enable debug logging: `logging.level.com.example.oidc=DEBUG`

### Session Not Cleared

1. Ensure all cookies are being deleted
2. Check if browser is caching credentials
3. Verify OIDC provider supports logout

### Back-Channel Logout Not Working

1. Verify the logout URI is accessible from the OIDC provider
2. Check if the provider supports back-channel logout
3. Ensure logout tokens are properly validated