package com.apigateway.filter;

import com.apigateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RefreshScope
@Component
public class JwtFilter implements GatewayFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);

    @Autowired
    private RouterValidator routerValidator;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private RoleFilter roleFilter;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (routerValidator.isSecured.test(request)) {

            if (this.isAuthMissing(request))
                return this.onError(exchange, "Authorization header is missing in request", UNAUTHORIZED);

            final String token = this.getAuthHeader(request).substring(7);

            if (jwtUtil.isInvalid(token))
                return this.onError(exchange, "Authorization header is invalid", UNAUTHORIZED);

            var roles = jwtUtil.extractAllClaims(token).get("roles", List.class);
            var method = exchange.getRequest().getMethod().toString();
            var path = exchange.getRequest().getURI().getPath();
            var access = roleFilter.hasAccess(path, method, roles);

            if (!access) {
                this.onError(exchange, "Unauthorized request", FORBIDDEN);
            }

//            this.populateRequestWithHeaders(exchange, token);
        }
        return chain.filter(exchange);
    }
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        log.error(err);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty(AUTHORIZATION).get(0);
    }

    private boolean isAuthMissing(ServerHttpRequest request) {
        return !request.getHeaders().containsKey(AUTHORIZATION);
    }

    private void populateRequestWithHeaders(ServerWebExchange exchange, String token) {
        Claims claims = jwtUtil.getAllClaimsFromToken(token);
        exchange.getRequest().mutate()
                .header("id", String.valueOf(claims.get("id")))
                .header("role", String.valueOf(claims.get("role")))
                .build();
    }
}
