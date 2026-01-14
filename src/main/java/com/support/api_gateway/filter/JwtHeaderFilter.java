package com.support.api_gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class JwtHeaderFilter implements GlobalFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // 🔒 IMPORTANT: Do NOT touch auth endpoints
        String path = exchange.getRequest().getURI().getPath();
        if (path.startsWith("/auth")) {
            return chain.filter(exchange);
        }

        return exchange.getPrincipal()
                .filter(Authentication.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .flatMap(auth -> {

                    Jwt jwt = auth.getToken();

                    String email = jwt.getSubject();
                    String role = jwt.getClaimAsString("role");

                    System.out.println("Gateway extracted JWT → " + email + " | " + role);

                    ServerHttpRequest mutatedRequest = exchange.getRequest()
                            .mutate()
                            .header("X-User-Email", email)
                            .header("X-User-Role", role)
                            .build();

                    return chain.filter(
                            exchange.mutate().request(mutatedRequest).build()
                    );
                })
                // 🔄 If no JWT (should not happen for /support, but safe)
                .switchIfEmpty(chain.filter(exchange));
    }
}