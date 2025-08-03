package com.example.oidc.config;

import com.example.oidc.annotation.Username;
import com.example.oidc.security.SecurityContextHelper;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolver for @Username annotation in controller method parameters.
 * Automatically injects the current user's username.
 */
@Component
public class UsernameArgumentResolver implements HandlerMethodArgumentResolver {
    
    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.getParameterAnnotation(Username.class) != null &&
               parameter.getParameterType().equals(String.class);
    }
    
    @Override
    public Object resolveArgument(
		MethodParameter parameter, 
		ModelAndViewContainer mavContainer,
		NativeWebRequest webRequest, 
		WebDataBinderFactory binderFactory
	) throws Exception {
        
        Username usernameAnnotation = parameter.getParameterAnnotation(Username.class);
        if (usernameAnnotation == null) {
            return null;
        }
        
        boolean truncated = usernameAnnotation.truncated();
        return SecurityContextHelper.getUsername(truncated);
    }
}