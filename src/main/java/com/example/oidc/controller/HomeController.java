package com.example.oidc.controller;

import com.example.oidc.annotation.Username;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    
    @GetMapping("/")
    public String index() {
        return "index";
    }
    
    @GetMapping("/login")
    public String login() {
        return "login";
    }
    
    @GetMapping("/home")
    public String home(@AuthenticationPrincipal OidcUser principal, 
                      @Username String username,
                      Model model) {
        if (principal != null) {
            model.addAttribute("username", username); // Using @Username annotation
            model.addAttribute("email", principal.getEmail());
            model.addAttribute("name", principal.getFullName());
        }
        return "home";
    }
}