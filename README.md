# Spring Boot OIDC with Multiple Secrets

A Spring Boot application that demonstrates OIDC authentication with support for multiple client secrets and automatic rotation.

## Features

- Spring Boot 3.5.4 with Java 17
- OIDC/OAuth2 authentication
- Multiple client secrets support
- Automatic secret rotation with configurable polling interval
- Internal polling process (only starts when multiple secrets are configured)
- Minimal web UI with Thymeleaf
- Zero downtime during secret rotation
- API endpoints return 401 instead of redirecting to login
- 30-minute session inactivity timeout
- Secure session cookie configuration
- Automatic cookie cleanup on logout

## How It Works

1. Configure multiple client secrets in `application.yml`
2. If more than one secret is configured, the `CustomClientRegistrationRepository` automatically starts an internal polling thread
3. The polling process validates the current secret at the configured interval
4. If the current secret fails, it automatically tries the other configured secrets
5. Once a valid secret is found, it becomes the active secret
6. This ensures minimal downtime when rotating secrets
7. If only one secret is configured, no polling occurs

## Configuration

Edit `src/main/resources/application.yml`:

```yaml
app:
  oidc:
    issuer-uri: https://your-oidc-provider.com
    client-id: your-client-id
    client-secrets:
      - current-secret
      - new-secret-to-rotate-to
      - backup-secret
    redirect-uri: http://localhost:8080/login/oauth2/code/oidc
    secret-rotation-interval-ms: 60000  # 1 minute
```

## Running the Application

```bash
mvn spring-boot:run
```

Access the application at http://localhost:8080

## Security Features

### API Endpoints
- Requests to `/api/**` return 401 Unauthorized when not authenticated (no redirect)
- Other endpoints redirect to login page when not authenticated

### Session Management
- 30-minute inactivity timeout
- Secure cookie configuration (httpOnly, sameSite=lax)
- Automatic session and cookie cleanup on logout
- Single concurrent session per user

### Example API Usage
```bash
# Unauthenticated request returns 401
curl -i http://localhost:8080/api/user
# HTTP/1.1 401 Unauthorized

# Authenticated request returns user data
curl -i -H "Cookie: JSESSIONID=..." http://localhost:8080/api/user
# HTTP/1.1 200 OK
# {"username":"john.doe","email":"john@example.com","authenticated":true}
```

## Secret Rotation Process

1. Add the new secret to the `client-secrets` list in configuration
2. Restart the application
3. The application will continue using the current working secret
4. Once the new secret is activated on the OIDC provider, the application will automatically switch to it
5. Remove old secrets from configuration after successful rotation"# spring-boot-oidc-multi-secret" 
