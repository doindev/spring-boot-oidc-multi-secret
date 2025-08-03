package com.example.entra;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

/**
 * Security configuration for Microsoft Entra ID (Azure AD) authentication.
 * This configuration is active when security.type=entra
 */
@Slf4j
@Configuration
@EnableWebSecurity
@ConditionalOnProperty(name = "security.type", havingValue = "entra")
@Order(1)
public class EntraSecurityConfig {
    
    private final EntraCorrelationIdFilter entraCorrelationIdFilter;
    private final EntraTokenRefreshFilter entraTokenRefreshFilter;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;
    
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}")
    private String issuerUri;
    
    @Value("${entra.allowed-groups:}")
    private List<String> allowedGroups;
    
    @Value("${entra.allowed-app-roles:}")
    private List<String> allowedAppRoles;
    
    public EntraSecurityConfig(
            EntraCorrelationIdFilter entraCorrelationIdFilter,
            EntraTokenRefreshFilter entraTokenRefreshFilter,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {
        this.entraCorrelationIdFilter = entraCorrelationIdFilter;
        this.entraTokenRefreshFilter = entraTokenRefreshFilter;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientRepository = authorizedClientRepository;
        log.info("Microsoft Entra ID security configuration initialized");
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Add correlation ID filter at the very beginning
            .addFilterBefore(entraCorrelationIdFilter, WebAsyncManagerIntegrationFilter.class)
            
            // Add Entra token refresh filter after OAuth2 login
            .addFilterAfter(entraTokenRefreshFilter, WebAsyncManagerIntegrationFilter.class)
            
            // CORS configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // CSRF configuration
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/webhook/**") // Ignore CSRF for webhooks if needed
            )
            
            // Session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation().migrateSession()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            )
            
            // Authorization rules
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/error", "/health", "/security-info").permitAll()
                .requestMatchers("/login/**", "/oauth2/**").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            
            // OAuth2 Login (for web UI)
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/entra")
                .defaultSuccessUrl("/home", true)
                .failureUrl("/login?error=true")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(new EntraOAuth2UserService(allowedGroups, allowedAppRoles))
                    .oidcUserService(new EntraOidcUserService(allowedGroups, allowedAppRoles))
                )
            )
            
            // OAuth2 Resource Server (for API endpoints)
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )
            
            // Logout configuration
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler(oidcLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID", "XSRF-TOKEN")
            )
            
            // Exception handling
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    (request, response, authException) -> {
                        log.debug("Unauthorized access to API endpoint: {}", request.getRequestURI());
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                    },
                    request -> request.getRequestURI().startsWith("/api/")
                )
                .defaultAuthenticationEntryPointFor(
                    (request, response, authException) -> {
                        log.debug("Redirecting to Entra login for: {}", request.getRequestURI());
                        response.sendRedirect("/oauth2/authorization/entra");
                    },
                    request -> !request.getRequestURI().startsWith("/api/")
                )
            );
        
        return http.build();
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        // Microsoft Entra ID uses the issuer URI to fetch the JWK Set
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }
    
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        EntraJwtAuthenticationConverter converter = new EntraJwtAuthenticationConverter();
        converter.setAllowedGroups(allowedGroups);
        converter.setAllowedAppRoles(allowedAppRoles);
        return converter;
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(
            "http://localhost:3000",
            "http://localhost:4200",
            "https://*.azurewebsites.net"
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(Duration.ofHours(1));
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler handler = 
            new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        handler.setPostLogoutRedirectUri("{baseUrl}");
        return handler;
    }
}