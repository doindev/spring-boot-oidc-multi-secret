# Single Page Application (SPA) Configuration

This application supports serving Single Page Applications (SPAs) like Angular, React, or Vue.js with proper client-side routing support.

## How It Works

When SPA mode is enabled:
1. **404 Handling**: Any URL that doesn't match a server route returns the SPA's index.html
2. **Client-Side Routing**: The SPA's router (e.g., Angular Router) takes over and handles the route
3. **Not Found Route**: Unknown routes can be handled by the SPA's `/not-found` route with the original path as a query parameter

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
3. **Static Resources**: Served directly (JS, CSS, images)
4. **Unknown Routes**: Return index.html, letting the SPA handle routing

### Client-Side Behavior

1. **Direct Navigation**: When users navigate to `/some/path`:
   - Server returns index.html
   - Angular router reads the URL and routes to the appropriate component
   - If route doesn't exist, Angular can redirect to `/not-found?page=/some/path`

2. **In-App Navigation**: Works normally through Angular router

## Example Flow

1. User visits `/products/123` (doesn't exist on server)
2. Server returns `index.html` (with SPA enabled)
3. Angular app loads and router activates
4. Angular router either:
   - Routes to ProductComponent if the route exists
   - Redirects to `/not-found?page=/products/123` if not

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

To test SPA configuration:

1. Enable SPA mode in application.yml
2. Place your Angular build output in `src/main/resources/static/`
3. Start the application
4. Try accessing various routes:
   - `/` - Should load your SPA
   - `/about` - Should load your SPA (handled by Angular router)
   - `/api/users` - Should return 404 (not index.html)
   - `/nonexistent` - Should load your SPA, Angular shows not-found

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