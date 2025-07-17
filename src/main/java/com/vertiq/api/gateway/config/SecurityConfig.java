package com.vertiq.api.gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                // 1) disable CSRF (if you aren’t using cookies for state-changing operations)
                .csrf(csrf -> csrf.disable())
                // 2) disable Basic Auth and form login so the browser never prompts
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                // 3) on auth failures just return 401/403 with no WWW-Authenticate header
                .exceptionHandling(ex -> ex
                .authenticationEntryPoint((exchange, ex2) -> {
                    logger.warn("API Gateway 401 Unauthorized for path: {}", exchange.getRequest().getPath());
                    return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED));
                })
                .accessDeniedHandler((exchange, ex3) -> {
                    logger.warn("API Gateway 403 Forbidden for path: {}", exchange.getRequest().getPath());
                    return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN));
                })
                )
                // 4) your route rules
                .authorizeExchange(authz -> authz
                .pathMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                .pathMatchers(
                        "/auth/v1/login", "/auth/v1/signup",
                        "/auth/v1/refresh", "/auth/v1/logout", "/auth/v1/oidc/google"
                ).permitAll()
                .anyExchange().permitAll() // TEMP: allow all for debugging
                );

        SecurityWebFilterChain chain = http.build();
        return chain;
    }

    @Bean
    public WebFilter loggingWebFilter() {
        return (exchange, chain) -> {
            logger.info("API Gateway received request: {} {}", exchange.getRequest().getMethod(), exchange.getRequest().getPath());
            return chain.filter(exchange);
        };
    }
}
