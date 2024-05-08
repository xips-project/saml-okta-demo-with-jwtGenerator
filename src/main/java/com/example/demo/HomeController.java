package com.example.demo;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import okhttp3.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


import java.io.IOException;
import java.util.Collection;
import java.util.UUID;

@RestController
public class HomeController {

    private final JWTService jwtService;

    public HomeController(JWTService jwtService) {
        this.jwtService = jwtService;
    }

    @RequestMapping("/")
    public ResponseEntity<?> home(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model, Saml2Authentication authentication, HttpServletResponse response) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());

        System.out.println(principal.getAttributes());
        System.out.println(authentication.getSaml2Response());

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        String jwt = jwtService.generateToken(principal.getName(), authorities);

        System.out.println(authorities);

        String username = principal.getName();

        Cookie cookie = new Cookie("access_token", jwt);
        cookie.setPath("/");
        response.addCookie(cookie);

        HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + jwt);
        headers.add(HttpHeaders.LOCATION, "http://localhost:4200");
        model.addAttribute("token", jwt);
        model.addAttribute("username", username);
        model.addAttribute("authorities", authorities.stream().toList());
        UUID uuid = UUID.randomUUID();
        System.out.println(uuid);
        System.out.println(jwt);

        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }





}













