package com.apigateway.config;

import com.apigateway.filter.JwtFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

    private final JwtFilter jwtFilter;

    public RouteConfig(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Value("${services.auth}")
    private String authURI;
    @Value("${services.property}")
    private String propertyURI;
    @Value("${services.reservation}")
    private String reservationURI;


    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("ms-auth", r -> r
                        .path("/api/v1/user/**", "/api/v1/role/**")
                        .uri(authURI))
                .route("ms-property", r -> r
                        .path("/api/v1/attribute-category/**", "/api/v1/attribute/**", "api/v1/category",
                                "/api/v1/country/**", "api/v1/location/**", "api/v1/place-type", "/api/v1/property",
                                "/api/v1/property-type/**", "api/v1/region/**")
                        .filters(f -> f.filter(jwtFilter))
                        .uri(propertyURI))
                .route("ms-reservation", r -> r
                        .path("/api/v1/booking/**")
                        .filters(f -> f.filter(jwtFilter))
                        .uri(reservationURI))
                .build();
    }
}
