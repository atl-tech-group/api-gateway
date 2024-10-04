package com.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Date;

@Component
public class JwtFilter implements GatewayFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);

    @Value("${jwt.secret.key}")
    private String SECRET_KEY;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String token = extractJwtFromRequest(exchange.getRequest().getHeaders().getFirst("Authorization"));

        if (token == null || !validateToken(token)) {
            log.error("Invalid or missing JWT Token");
            return handleUnauthorized(exchange);
        }

        Jws<Claims> claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .build().parseClaimsJws(token);

        String username = claims.getBody().get("username", String.class);
        Long userId = claims.getBody().get("userId", Long.class);

        log.info("User authenticated: username={}, userId={}", username, userId);

        return chain.filter(exchange);
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    private String extractJwtFromRequest(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(SECRET_KEY).build().parseClaimsJws(token);
            return !claimsJws.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }
}
