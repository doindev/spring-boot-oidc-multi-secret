# OIDC Authentication Process Flow

## Complete Authentication Flow with `findByRegistrationId` Calls

```
USER                    SPRING BOOT APP                    OIDC PROVIDER
 |                            |                                  |
 |--- 1. GET /home -------->  |                                  |
 |                            |                                  |
 |<-- 302 Redirect to /login--|                                  |
 |                            |                                  |
 |--- 2. GET /login -------->  |                                  |
 |                            |                                  |
 |--- 3. Click "Login" ------>  |                                  |
 |    GET /oauth2/authorization/oidc-0                           |
 |                            |                                  |
 |                     [findByRegistrationId called #1]          |
 |                     - Get authorization endpoint              |
 |                     - Get client ID                           |
 |                     - Get redirect URI                        |
 |                     - Get scopes                              |
 |                            |                                  |
 |<-- 302 Redirect -----------|                                  |
 |    to OIDC Provider        |                                  |
 |    with parameters:        |                                  |
 |    - client_id             |                                  |
 |    - redirect_uri          |                                  |
 |    - scope                 |                                  |
 |    - state                 |                                  |
 |    - response_type=code    |                                  |
 |                            |                                  |
 |--------------------------- 4. GET /authorize ---------------->|
 |                            |                                  |
 |<-------------------------- Login Form -----------------------|
 |                            |                                  |
 |--- 5. Submit Credentials ----------------------------------->|
 |                            |                                  |
 |<-- 302 Redirect with code -----------------------------------|
 |    to redirect_uri         |                                  |
 |                            |                                  |
 |--- 6. GET /login/oauth2/code/oidc?code=XXX&state=YYY ------->|
 |                            |                                  |
 |                     [findByRegistrationId called #2]          |
 |                     - Validate state parameter                |
 |                     - Get token endpoint                      |
 |                     - Get client secret (IMPORTANT!)          |
 |                            |                                  |
 |                            |--- 7. POST /token -------------->|
 |                            |    Authorization: Basic          |
 |                            |    (client_id:client_secret)     |
 |                            |    grant_type=authorization_code|
 |                            |    code=XXX                     |
 |                            |                                  |
 |                            |<-- Access Token + ID Token ------|
 |                            |                                  |
 |                     [findByRegistrationId called #3]          |
 |                     - Get JWK Set URI (to validate ID token)  |
 |                            |                                  |
 |                            |--- 8. GET /jwks --------------->|
 |                            |                                  |
 |                            |<-- JWK Set --------------------|
 |                            |                                  |
 |                     [findByRegistrationId called #4]          |
 |                     - Get user info endpoint                  |
 |                            |                                  |
 |                            |--- 9. GET /userinfo ----------->|
 |                            |    Authorization: Bearer         |
 |                            |    <access_token>               |
 |                            |                                  |
 |                            |<-- User Info -------------------|
 |                            |                                  |
 |<-- 302 Redirect to /home --|                                  |
 |    (Authenticated)         |                                  |
 |                            |                                  |
 |--- 10. GET /home --------->|                                  |
 |                            |                                  |
 |<-- Welcome Page -----------|                                  |
 |    (Shows user info)       |                                  |
```

## Key Points About `findByRegistrationId` Calls:

### Call #1 - Building Authorization URL
- **When**: User initiates login
- **Purpose**: Get OIDC provider endpoints and client configuration
- **What's needed**: Authorization endpoint, client ID, redirect URI, scopes

### Call #2 - Authorization Code Callback
- **When**: OIDC provider redirects back with code
- **Purpose**: Validate callback and prepare for token exchange
- **What's needed**: Token endpoint, **client secret** (critical for rotation!)

### Call #3 - Token Validation
- **When**: After receiving tokens
- **Purpose**: Validate ID token signature
- **What's needed**: JWK Set URI

### Call #4 - Fetching User Info
- **When**: After token validation
- **Purpose**: Get additional user details
- **What's needed**: User info endpoint

## Secret Rotation Impact:

Your implementation with the polling mechanism ensures:

1. **Between any of these calls**, if the secret rotates, the next call gets the new secret
2. **Most critical**: Call #2 uses the secret for token exchange
3. **Seamless transition**: No authentication in progress is disrupted

## Additional Scenarios:

### Token Refresh Flow:
```
When access token expires:
|--- POST /token ----------->|
|    grant_type=refresh_token|
|    refresh_token=XXX       |
|    [findByRegistrationId]  |
|    (needs client secret)   |
```

### Logout Flow:
```
When user logs out:
|--- POST /logout ---------->|
|    [findByRegistrationId]  |
|    (may need end_session)  |
```

This is why your design of always returning the current active registration is perfect - Spring Security gets the latest valid secret exactly when it needs it!