package com.support.api_gateway.filter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;

import reactor.core.publisher.Mono;

@Component
public class JwtLoggingFilter implements GlobalFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtLoggingFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        return exchange.getPrincipal()
                .cast(Authentication.class)
                .doOnNext(auth -> {

                    if (auth instanceof JwtAuthenticationToken jwtAuth) {
                        Jwt jwt = jwtAuth.getToken();

                        String subject = jwt.getSubject(); // email
                        String role = jwt.getClaimAsString("role");
                        Object exp = jwt.getExpiresAt();

                        log.info("🔐 JWT CLAIMS:");
                        log.info("➡ Subject (email): {}", subject);
                        log.info("➡ Role: {}", role);
                        log.info("➡ Expires At: {}", exp);
                    }

                })
                .then(chain.filter(exchange));
    }
}

