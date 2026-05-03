package com.deharri.gateway.filter;

import com.deharri.gateway.jwt.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Global authentication filter for API Gateway.
 * Validates JWT tokens and propagates user information to downstream services.
 * 
 * Public endpoints (auth routes) are excluded from authentication.
 */
@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationFilter.class);

    private final JwtUtil jwtUtil;

    /**
     * List of path patterns that don't require authentication.
     * These are typically auth endpoints like login, register, etc.
     */
    private static final List<String> PUBLIC_PATHS = List.of(
            "/ums/api/v1/auth/register",
            "/ums/api/v1/auth/login",
            "/ums/api/v1/auth/refresh",
            "/ums/api/v1/auth/logout",
            "/ums/api/v1/auth/send-otp",
            "/ums/api/v1/agencies/internal",
            // Dev-only data wipe endpoints (used by start.html). NOT for production.
            "/ums/api/v1/dev",
            "/jobs/api/v1/dev",
            "/payments/api/v1/dev",
            "/chat/api/v1/dev",
            "/ums/api/v1/users",           // Public user list
            "/ums/api/v1/workers/nearby",         // Public nearby worker search
            "/ums/api/v1/workers/internal",      // Service-to-service worker activation
            "/ums/api/v1/internal",              // Service-to-service internal calls
            "/chat/ws",                          // WebSocket — JWT validated by chat service itself
            "/ums/swagger-ui",
            "/ums/v3/api-docs",
            "/ums/swagger-resources",
            "/chat/swagger-ui",
            "/chat/v3/api-docs",
            "/chat/swagger-resources",
            "/jobs/swagger-ui",
            "/jobs/v3/api-docs",
            "/jobs/swagger-resources",
            "/payments/swagger-ui",
            "/payments/v3/api-docs",
            "/payments/swagger-resources",
            "/actuator"
    );

    public AuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        String method = request.getMethod().name();

        log.debug("Processing request: {} {}", method, path);

        // Check if the endpoint is public
        if (isPublicEndpoint(path)) {
            log.debug("Public endpoint accessed: {}", path);
            return chain.filter(exchange);
        }

        // Extract JWT from Authorization header
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // SSE EventSource cannot set headers — fall back to ?token=… for the events path.
        if ((authHeader == null || !authHeader.startsWith("Bearer "))
                && path.startsWith("/jobs/api/v1/events/")) {
            String q = request.getQueryParams().getFirst("token");
            if (q != null && !q.isBlank()) {
                authHeader = "Bearer " + q;
            }
        }

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for: {}", path);
            return onError(exchange, "Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        try {
            // Validate JWT
            if (!jwtUtil.validateToken(token)) {
                log.warn("Invalid or expired token for request: {}", path);
                return onError(exchange, "Invalid or expired token", HttpStatus.UNAUTHORIZED);
            }

            // Extract user information from JWT
            String userId = jwtUtil.extractUserId(token);
            String username = jwtUtil.extractUsername(token);
            String email = jwtUtil.extractEmail(token);
            List<String> roles = jwtUtil.extractRoles(token);

            log.debug("Authenticated user: {} (ID: {}) accessing: {}", username, userId, path);

            // Add user info to request headers for downstream services
            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id", userId != null ? userId : "")
                    .header("X-Username", username != null ? username : "")
                    .header("X-User-Email", email != null ? email : "")
                    .header("X-User-Roles", roles != null ? String.join(",", roles) : "")
                    .build();

            // Continue with modified request
            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            log.error("JWT validation failed for request {}: {}", path, e.getMessage());
            return onError(exchange, "JWT validation failed: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Check if the path matches any public endpoint pattern.
     */
    private boolean isPublicEndpoint(String path) {
        return PUBLIC_PATHS.stream().anyMatch(publicPath -> 
                path.equals(publicPath) || path.startsWith(publicPath + "/") || path.startsWith(publicPath)
        );
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add("Content-Type", "application/json");
        
        String body = String.format("{\"error\": \"%s\", \"status\": %d}", message, status.value());
        
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body.getBytes())));
    }

    @Override
    public int getOrder() {
        return -1; // Execute before routing
    }
}