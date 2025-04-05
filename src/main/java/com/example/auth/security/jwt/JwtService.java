package com.example.auth.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    public String generateToken(UserDetails userDetails, Duration tokenLifetime) {
        Map<String, Object> claims = new HashMap<>();
        List<String> rolesList = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        claims.put("roles", rolesList);

        Date issuedDate = new Date();
        Date expiredDate = new Date(issuedDate.getTime() + tokenLifetime.toMillis());

        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        log.info("token for user [{}] success generated with [{}sec] lifetime", userDetails.getUsername(), tokenLifetime.getSeconds());
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(issuedDate)
                .expiration(expiredDate)
                .signWith(key)
                .compact();
    }

    public String getUsername(String token) {
        return getClaimFromToken(token, "sub", String.class);
    }

    public List getRoles(String token) {
        return getClaimFromToken(token, "roles", List.class);
    }

    public boolean isExpired(String token) {
        return getClaimFromToken(token, "exp", Date.class).before(new Date());
    }

    public Date getExpirationDate(String token) {
        return getClaimFromToken(token, "exp", Date.class);
    }

    private Claims getAllClaimsFromToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private  <T> T getClaimFromToken(String token, String claimKey, Class<T> claimType) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.get(claimKey, claimType);
    }
}
