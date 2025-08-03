# Single Page Application (SPA) Configuration

This application supports serving Single Page Applications (SPAs) like Angular, React, or Vue.js with proper client-side routing support.

## How It Works

When SPA mode is enabled:
1. **404 Handling**: Any URL that doesn't match a server route is forwarded to the configured `not-found-url`
2. **Forward Behavior**: The server forwards (not redirects) to preserve the original URL in the browser
3. **Client-Side Routing**: The SPA's router (e.g., Angular Router) takes over and handles the route
4. **Not Found Route**: The SPA should handle the configured not-found route with the original path as a query parameter

## Configuration

### Enable SPA Mode

In `application.yml`:

```yaml
spa:
  enabled: true
  index-url: index.html  # Path to your SPA's index file (can be any name)
  not-found-url: /not-found?page={notFoundUrl}
```

### Using Custom Index File Names

The `index-url` property allows you to specify any filename for your SPA:

```yaml
spa:
  index-url: app.html           # Custom name
  # OR
  index-url: angular-app.html   # Angular specific
  # OR  
  index-url: spa-index.html     # Descriptive name
  # OR
  index-url: my-application.html # Any name you prefer
```

The controller will look for this file in the following locations (in order):
1. `/static/` directory
2. `/templates/` directory  
3. `/public/` directory
4. Classpath root

### Angular Router Example

In your Angular app, configure the router to handle the not-found route:

```typescript
// app-routing.module.ts
const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'about', component: AboutComponent },
  { path: 'not-found', component: NotFoundComponent },
  { path: '**', redirectTo: '/not-found' }
];

// not-found.component.ts
export class NotFoundComponent implements OnInit {
  originalPath: string;
  
  constructor(private route: ActivatedRoute) {}
  
  ngOnInit() {
    this.route.queryParams.subscribe(params => {
      this.originalPath = params['page'] || 'unknown';
    });
  }
}
```

## How Routing Works

### Server-Side Behavior

1. **Known Routes**: Served normally by Spring controllers
2. **API Routes**: Return proper 404 errors (not index.html)
3. **Static Resources**: Served directly if they exist, 404 if not found
4. **Unknown Routes**: Forward to the configured `not-found-url` with the original path as a parameter

### Forward vs Redirect

The implementation uses **forward** instead of redirect, which means:
- The browser URL remains unchanged (shows the original path)
- The server internally forwards the request to the not-found handler
- The not-found handler returns the SPA's index.html
- The SPA's router can read the original URL and handle routing

### Client-Side Behavior

1. **Direct Navigation**: When users navigate to `/some/path`:
   - Server returns index.html
   - Angular router reads the URL and routes to the appropriate component
   - If route doesn't exist, Angular can redirect to `/not-found?page=/some/path`

2. **In-App Navigation**: Works normally through Angular router

## Example Flow

1. User visits `/products/123` (doesn't exist on server)
2. Server detects 404 and forwards to `/not-found?page=/products/123`
3. The `/not-found` route handler returns `index.html` content
4. Browser URL remains `/products/123` (due to forward, not redirect)
5. Angular app loads and reads the current URL
6. Angular router either:
   - Routes to ProductComponent if the route exists
   - Shows a not-found component for unrecognized routes

## Excluding Paths

Some paths should return real 404s instead of index.html:

```yaml
spa:
  exclude-patterns:
    - /api/**        # API endpoints
    - /actuator/**   # Actuator endpoints
    - /**/*.js       # JavaScript files
    - /**/*.css      # CSS files
    - /**/*.png      # Images
```

## Testing

### Manual Testing

To test SPA configuration:

1. Enable SPA mode in application.yml:
   ```yaml
   spa:
     enabled: true
     not-found-url: /not-found?page={notFoundUrl}
   ```

2. Place your index.html in `src/main/resources/static/`

3. Start the application:
   ```bash
   mvn spring-boot:run
   ```

4. Test various routes:
   - `http://localhost:8080/` - Should load your SPA
   - `http://localhost:8080/products` - Should forward to `/not-found?page=/products` and load SPA
   - `http://localhost:8080/api/users` - Should return 404 (not index.html)
   - `http://localhost:8080/unknown.js` - Should return 404 (not index.html)

### Important Note on Testing

The forwarding behavior works correctly in a running application but may not work as expected in MockMvc tests due to how Spring Boot's error handling works in test environments. The `SpaErrorController` relies on Spring Boot's error handling mechanism which processes 404s through the `/error` endpoint.

### Using the Test Script

A test script is provided to verify the behavior:

```bash
# Windows
test-spa.bat

# Linux/Mac (create similar script)
./test-spa.sh
```

## Security Considerations

- SPA mode only affects 404 handling
- Authentication/authorization still applies
- API endpoints are not affected
- Static resources are served with appropriate cache headers

## Controllers

### SpaErrorController
- Handles 404 errors when SPA is enabled
- Returns index.html content for unknown routes
- Excludes API and static resource paths

### SpaRoutingController
- Provides explicit handling for SPA routes
- Handles `/not-found` endpoint
- Can be extended for additional SPA-specific endpoints