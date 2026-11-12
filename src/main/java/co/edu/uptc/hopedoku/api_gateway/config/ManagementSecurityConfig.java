package co.edu.uptc.hopedoku.api_gateway.config;

import org.springframework.boot.security.autoconfigure.actuate.web.reactive.EndpointRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.StringUtils;

import java.net.InetSocketAddress;

@Configuration(proxyBeanMethods = false)
public class ManagementSecurityConfig {

    @Bean
    @Order(1)
    SecurityWebFilterChain prometheusEndpointSecurity(
            ServerHttpSecurity http,
            @Value("${spring.security.user.name:metrics}") String username,
            @Value("${spring.security.user.password:}") String password,
            @Value("${management.server.port:8766}") int managementPort) {
        ReactiveAuthenticationManager metricsAuthenticationManager =
                createMetricsAuthenticationManager(username, password);
        return http
                .securityMatcher(managementEndpointOnPort(managementPort))
                .authorizeExchange(authorize -> authorize.anyExchange().authenticated())
                .httpBasic(basic -> basic.authenticationManager(metricsAuthenticationManager))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    private static ReactiveAuthenticationManager createMetricsAuthenticationManager(String username, String password) {
        if (!StringUtils.hasText(password)) {
            throw new IllegalStateException("METRICS_SCRAPE_PASSWORD must be configured");
        }

        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        var user = User.withUsername(username)
                .password(passwordEncoder.encode(password))
                .roles("METRICS")
                .build();
        var userDetailsService = new MapReactiveUserDetailsService(user);
        var authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
        authenticationManager.setPasswordEncoder(passwordEncoder);
        return authenticationManager;
    }

    @Bean
    @Order(2)
    SecurityWebFilterChain gatewayApplicationSecurity(ServerHttpSecurity http) {
        return http
                .authorizeExchange(authorize -> authorize
                        .pathMatchers("/actuator/prometheus", "/actuator/prometheus/**").denyAll()
                        .anyExchange().permitAll())
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

  private static ServerWebExchangeMatcher managementEndpointOnPort(int managementPort) {
    ServerWebExchangeMatcher endpointMatcher = EndpointRequest.to("prometheus");

    return exchange -> endpointMatcher.matches(exchange).flatMap(result -> {
        if (!result.isMatch()) {
            return ServerWebExchangeMatcher.MatchResult.notMatch();
        }

        InetSocketAddress localAddress = exchange.getRequest().getLocalAddress();

        return localAddress != null && localAddress.getPort() == managementPort
                ? reactor.core.publisher.Mono.just(result)
                : ServerWebExchangeMatcher.MatchResult.notMatch();
    });
}
}
