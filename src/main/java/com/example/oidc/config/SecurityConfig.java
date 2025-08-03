package com.example.oidc.config;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import com.example.oidc.security.OidcTokenRefreshFilter;
import com.example.oidc.filter.CorrelationIdFilter;

@Configuration
@EnableWebSecurity
@ConditionalOnProperty(name = "security.type", havingValue = "oidc")
public class SecurityConfig {
    
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OidcLogoutSuccessHandler oidcLogoutSuccessHandler;
    private final OidcTokenRefreshFilter oidcTokenRefreshFilter;
    private final CorrelationIdFilter correlationIdFilter;
    
    public SecurityConfig(
		ClientRegistrationRepository clientRegistrationRepository,
		OidcLogoutSuccessHandler oidcLogoutSuccessHandler,
		OidcTokenRefreshFilter oidcTokenRefreshFilter,
		CorrelationIdFilter correlationIdFilter
	) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.oidcLogoutSuccessHandler = oidcLogoutSuccessHandler;
        this.oidcTokenRefreshFilter = oidcTokenRefreshFilter;
        this.correlationIdFilter = correlationIdFilter;
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        
        http
            // Add correlation ID filter at the very beginning
            .addFilterBefore(correlationIdFilter, org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter.class)
            // CORS configuration
            .cors(cors -> {
            	CorsConfiguration configuration = new CorsConfiguration();
	                configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:4200")); // Add your frontend URLs
	                configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
	                configuration.setAllowedHeaders(Arrays.asList("*"));
	                configuration.setAllowCredentials(true);
	                configuration.setExposedHeaders(Arrays.asList("Authorization", "X-Total-Count"));
	                configuration.setMaxAge(Duration.ofHours(1));
                
                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                	source.registerCorsConfiguration("/**", configuration);
                
            	cors.configurationSource(source);
            })
            // CSRF configuration
            .csrf(csrf -> {
            	// Configure CSRF with cookie repository
            	CookieCsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
	                csrfTokenRepository.setCookieName("XSRF-TOKEN");
	                csrfTokenRepository.setHeaderName("X-XSRF-TOKEN");
                
                // Create CSRF request handler
                CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
                	requestHandler.setCsrfRequestAttributeName("_csrf");
            	
            	csrf
	                .csrfTokenRepository(csrfTokenRepository)
	                .csrfTokenRequestHandler(requestHandler)
	                // Disable CSRF for API endpoints if needed
	                .ignoringRequestMatchers("/api/**");
            })
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/", "/error", "/login").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .clientRegistrationRepository(clientRegistrationRepository)
                .loginPage("/login")
                .defaultSuccessUrl("/", true)
            )
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    (request, response, authException) -> {
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                    },
                    request -> request.getRequestURI().startsWith("/api/")
                )
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    request -> !request.getRequestURI().startsWith("/api/")
                )
            )
            .sessionManagement(session -> {
            	SessionRegistry sessionRegistry = new org.springframework.security.core.session.SessionRegistryImpl();//optionally create your own SessionRegistry bean if needed to store and retrieve info from db maybe
            	
            	session
	                .sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED)
	                .invalidSessionStrategy((request, response) -> {
	                    try {
	                        if (request.getRequestURI().startsWith("/api/")) {
	                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session expired");
	                        } else {
	                            response.sendRedirect("/login");
	                        }
	                    } catch (IOException e) {
	                        throw new RuntimeException("Failed to handle invalid session", e);
	                    }
	                })
	                .sessionFixation(fixation -> fixation.migrateSession())
	                .maximumSessions(1)
	                    .maxSessionsPreventsLogin(false)
	                    .expiredSessionStrategy((event) -> {
	                        try {
	                            HttpServletResponse response = event.getResponse();
	                            if (event.getRequest().getRequestURI().startsWith("/api/")) {
	                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session expired");
	                            } else {
	                                response.sendRedirect("/login");
	                            }
	                        } catch (IOException e) {
	                            throw new RuntimeException("Failed to handle expired session", e);
	                        }
	                    })
	                    .sessionRegistry(sessionRegistry);
            })
            // OIDC Logout configuration
            .oidcLogout(oidc -> oidc
                .backChannel(backChannel -> backChannel
                    .logoutUri("/logout/connect/back-channel/{registrationId}")
                )
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
//                .logoutSuccessUrl("/")// Redirect to home page after logout, do not use this if you want to handle logout success with a custom handler
                .logoutSuccessHandler(oidcLogoutSuccessHandler)  // Use custom OIDC logout handler
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "SESSION", "XSRF-TOKEN")
                .clearAuthentication(true)
                .addLogoutHandler((request, response, authentication) -> {
                    // Custom logout handler to ensure all cookies are cleared
                    Cookie[] cookies = request.getCookies();
                    if (cookies != null) {
                        for (Cookie cookie : cookies) {
                            cookie.setValue("");
                            cookie.setPath("/");
                            cookie.setMaxAge(0);
                            cookie.setSecure(true); // Set to true in production, make this value default to true in the properties, populate from there
                            response.addCookie(cookie);
                        }
                    }
                })
            )
            // Add token refresh filter before authentication
            .addFilterBefore(oidcTokenRefreshFilter, UsernamePasswordAuthenticationFilter.class)
            ;
        
        return http.build();
    }
}