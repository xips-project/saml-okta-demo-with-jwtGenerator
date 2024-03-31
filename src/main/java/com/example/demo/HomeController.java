package com.example.demo;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import okhttp3.*;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;


import java.io.IOException;
import java.util.Collection;
import java.util.UUID;

@Controller
public class HomeController {

    private final JWTService jwtService;

    public HomeController(JWTService jwtService) {
        this.jwtService = jwtService;
    }

    @RequestMapping("/")
    public String home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model, Saml2Authentication authentication) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());

        System.out.println(principal.getAttributes());
        System.out.println(authentication.getSaml2Response());

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        String jwt = jwtService.generateToken(principal.getName(), authorities);

        System.out.println(authorities);

        String username = principal.getName();

        HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + jwt);
        model.addAttribute("token", jwt);
        model.addAttribute("username", username);
        model.addAttribute("authorities", authorities.stream().toList());
        UUID uuid = UUID.randomUUID();
        System.out.println(uuid);

        return "success";
    }



}













