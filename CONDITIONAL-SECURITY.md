# Conditional Security Configuration

This application supports multiple security configurations that can be switched using the `security.type` property.

## Configuration Options

### 1. OIDC Security (default)
```yaml
security:
  type: oidc
```

When `security.type=oidc`, the application uses OpenID Connect authentication with:
- Multiple client secret support with automatic rotation
- OIDC logout support
- Token refresh capability
- Session management with 30-minute timeout
- CORS and CSRF protection

### 2. Microsoft Entra ID (Azure AD)
```yaml
security:
  type: entra
```

When `security.type=entra`, the application uses Microsoft Entra ID authentication with:
- Support for Azure AD groups and app roles
- Token refresh capability specific to Entra
- Integration with Microsoft Graph API
- Support for both OAuth2 login (web) and JWT resource server (API)
- Tenant-specific configuration
- Group and app role based authorization

Configuration example:
```yaml
entra:
  tenant-id: your-azure-tenant-id
  allowed-groups: 
    - group-id-1
    - group-id-2
  allowed-app-roles:
    - Admin
    - User

spring:
  security:
    oauth2:
      client:
        registration:
          entra:
            client-id: your-azure-app-client-id
            client-secret: your-azure-app-client-secret
            scope:
              - openid
              - profile
              - email
              - https://graph.microsoft.com/User.Read
        provider:
          entra:
            issuer-uri: https://login.microsoftonline.com/${entra.tenant-id}/v2.0
      resourceserver:
        jwt:
          issuer-uri: https://login.microsoftonline.com/${entra.tenant-id}/v2.0
```

### 3. Basic Authentication
```yaml
security:
  type: basic
```

When `security.type=basic`, the application uses HTTP Basic authentication with:
- In-memory user store
- Predefined users:
  - Username: `user`, Password: `password` (ROLE_USER)
  - Username: `admin`, Password: `admin` (ROLE_USER, ROLE_ADMIN)
- Session management
- API endpoints return 401 for unauthorized access

### 4. No Security
```yaml
security:
  type: none
```

When `security.type=none`, all endpoints are open without authentication.
- Useful for development/testing
- CSRF protection is disabled
- All endpoints are publicly accessible

## How It Works

The conditional configuration uses Spring Boot's `@ConditionalOnProperty` annotation:

```java
@Configuration
@EnableWebSecurity
@ConditionalOnProperty(name = "security.type", havingValue = "oidc")
public class SecurityConfig {
    // OIDC configuration
}
```

Each security configuration class is annotated with the appropriate condition, so only one configuration is active at runtime based on the `security.type` property.

## Components Affected

### OIDC Components (conditional on `security.type=oidc`):
- `SecurityConfig` - Main OIDC security configuration
- `OAuth2ClientConfig` - OAuth2 client components
- `ClientRegistrationWithMultiSecretSupport` - Multi-secret support
- `ClientRegistrationRepositoryWithMultiSecretSupport` - Secret rotation repository
- `OidcLogoutSuccessHandler` - OIDC logout handler
- `OidcTokenRefreshFilter` - Token refresh filter

### Entra Components (conditional on `security.type=entra`):
- `EntraSecurityConfig` - Main Entra security configuration
- `EntraOAuth2ClientConfig` - Entra OAuth2 client components
- `EntraTokenRefreshFilter` - Entra-specific token refresh
- `EntraJwtAuthenticationConverter` - JWT claim extraction for Entra
- `EntraOAuth2UserService` - OAuth2 user loading for Entra
- `EntraOidcUserService` - OIDC user loading for Entra
- `EntraCorrelationIdFilter` - Request tracking for Entra
- `EntraTransactionContext` - Transaction context for Entra

## Checking Current Configuration

You can check the current security configuration by calling:
```
GET /security-info
```

Response example:
```json
{
    "securityType": "oidc",
    "authenticated": true,
    "principal": "john.doe@example.com",
    "authorities": ["ROLE_USER"],
    "authenticationType": "OAuth2AuthenticationToken"
}
```

## Switching Security Types

1. Update `application.yml`:
   ```yaml
   security:
     type: basic  # or 'oidc' or 'none'
   ```

2. Restart the application

3. The appropriate security configuration will be automatically loaded

## Testing Different Configurations

For testing, you can override the security type using command line arguments:
```bash
java -jar app.jar --security.type=basic
```

Or using environment variables:
```bash
SECURITY_TYPE=none java -jar app.jar
```

## Best Practices

1. **Production**: Always use `security.type=oidc` for production environments
2. **Development**: You might use `basic` or `none` for local development
3. **Testing**: Use appropriate security type based on what you're testing
4. **CI/CD**: Consider using different security types for different stages

## Note

- For OIDC configuration: The correlation ID filter (`CorrelationIdFilter`) is always active
- For Entra configuration: Uses its own `EntraCorrelationIdFilter` to avoid conflicts
- For Basic/None configurations: The OIDC correlation filter remains active

This ensures request tracking works in all configurations without component conflicts.