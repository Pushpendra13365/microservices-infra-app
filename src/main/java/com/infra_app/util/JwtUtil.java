package com.infra_app.util;

import com.infra_app.exception.CustomUnauthorizedException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtUtil {

    private final SecretKey secretKey;
    private final long accessTokenExpirationMs;

    public JwtUtil(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiration-ms}") long accessTokenExpirationMs) {

        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpirationMs = accessTokenExpirationMs;

        if (secretKey.getEncoded().length * 8 < 512) {
            throw new IllegalArgumentException("JWT secret key must be at least 512 bits (64 characters) for HS512 algorithm");
        }
    }

    public String generateAccessToken(String username, List<SimpleGrantedAuthority> authorities) {
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", authorities.stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plus(accessTokenExpirationMs, ChronoUnit.MILLIS)))
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }


    public String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public List<String> extractRoles(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("roles", List.class);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            throw new CustomUnauthorizedException("Invalid JWT signature");
        } catch (ExpiredJwtException e) {
            throw new CustomUnauthorizedException("Expired JWT token");
        } catch (UnsupportedJwtException e) {
            throw new CustomUnauthorizedException("Unsupported JWT token");
        } catch (IllegalArgumentException e) {
            throw new CustomUnauthorizedException("JWT claims string is empty");
        }
    }

    private Date extractExpiration(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
    }

    public Object getAccessTokenExpirationMs() {
        return null;
    }

    public boolean validateJwtToken(String token) {
        try {
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }
}