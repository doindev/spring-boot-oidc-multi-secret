package com.example.oidc.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to inject the current user's username into controller method parameters.
 * 
 * Usage:
 * <pre>
 * {@code
 * @GetMapping("/profile")
 * public String getProfile(@Username String username) {
 *     // username will be populated automatically
 * }
 * 
 * @GetMapping("/fullname")
 * public String getFullName(@Username(truncated = false) String username) {
 *     // username will include domain if present
 * }
 * }
 * </pre>
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
public @interface Username {
    
    /**
     * Whether to truncate the username by removing domain part.
     * If true, "user@domain.com" becomes "user"
     * If false, returns the full username including domain
     * 
     * @return true to truncate domain, false to keep full username
     */
    boolean truncated() default true;
}