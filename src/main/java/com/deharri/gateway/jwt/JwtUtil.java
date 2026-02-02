package com.deharri.gateway.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

/**
 * Utility class for JWT token validation and claim extraction.
 * Used by the API Gateway to validate incoming tokens and extract user information.
 */
@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${jwt.secret}")
    private String secret;

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Validates the JWT token.
     * 
     * @param token the JWT token to validate
     * @return true if token is valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            
            // Check if token is expired
            if (claims.getExpiration().before(new Date())) {
                log.debug("Token has expired");
                return false;
            }
            
            return true;
        } catch (ExpiredJwtException e) {
            log.debug("Token expired: {}", e.getMessage());
            return false;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Extracts user ID from token.
     */
    public String extractUserId(String token) {
        try {
            return extractClaim(token, claims -> claims.get("userId", String.class));
        } catch (Exception e) {
            log.debug("Could not extract userId from token");
            return null;
        }
    }

    /**
     * Extracts username (subject) from token.
     */
    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (Exception e) {
            log.debug("Could not extract username from token");
            return null;
        }
    }

    /**
     * Extracts email from token.
     */
    public String extractEmail(String token) {
        try {
            return extractClaim(token, claims -> claims.get("email", String.class));
        } catch (Exception e) {
            log.debug("Could not extract email from token");
            return null;
        }
    }

    /**
     * Extracts roles from token.
     */
    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        try {
            List<String> roles = extractClaim(token, claims -> claims.get("roles", List.class));
            return roles != null ? roles : Collections.emptyList();
        } catch (Exception e) {
            log.debug("Could not extract roles from token");
            return Collections.emptyList();
        }
    }

    /**
     * Extracts expiration date from token.
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}