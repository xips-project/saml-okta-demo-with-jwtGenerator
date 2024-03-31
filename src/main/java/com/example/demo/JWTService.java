package com.example.demo;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class JWTService {

    private static final String SECRET_KEY = "tBTeEle6IfDgxVXwH0s7bp0aPhQpW9Bw/tppsLTyMJ580KlH1g6ZULwpk5270frEhCtBoditMX9TlBhhZSrlSg==";

    private static final long EXPIRE_DATE = 1000*60*60;

    public String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + EXPIRE_DATE);

        Map<String, Object> claims = new HashMap<>();
        claims.put("role", authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        return Jwts.builder()
                .subject(username)
                .claims(claims)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(generateKey())
                .compact();
    }

    private SecretKey generateKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
