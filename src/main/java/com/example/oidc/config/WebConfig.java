package com.example.oidc.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

/**
 * Web MVC configuration to register custom argument resolvers.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    private final UsernameArgumentResolver usernameArgumentResolver;
    
    public WebConfig(UsernameArgumentResolver usernameArgumentResolver) {
        this.usernameArgumentResolver = usernameArgumentResolver;
    }
    
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(usernameArgumentResolver);
    }
}