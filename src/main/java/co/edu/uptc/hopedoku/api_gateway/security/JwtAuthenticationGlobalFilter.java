package co.edu.uptc.hopedoku.api_gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String ROLES_HEADER = "X-Roles";
    private static final String GATEWAY_SECRET_HEADER = "X-Gateway-Secret";

    private final String gatewaySecret;
    private final KeycloakTokenValidator tokenValidator;
    private final List<PathPattern> publicPaths;
    private final List<PathPattern> blockedPaths;

    public JwtAuthenticationGlobalFilter(
            KeycloakTokenValidator tokenValidator,
            @Value("${gateway.secret:}") String gatewaySecret) {
        this.gatewaySecret = gatewaySecret;
        this.tokenValidator = tokenValidator;

        PathPatternParser parser = PathPatternParser.defaultInstance;
        this.publicPaths = Stream.of(
                "/usuarios/swagger-ui/**", "/usuarios/swagger-ui.html", "/usuarios/v3/api-docs/**",
                "/casos/docs/**", "/casos/docs-json",
                "/partidas/docs/**", "/partidas/redoc", "/partidas/openapi.json")
                .map(parser::parse).toList();

        PathPatternParser insensitive = new PathPatternParser();
        insensitive.setCaseSensitive(false);
        this.blockedPaths = Stream.of(
                "/usuarios/users/*/results/**",
                "/casos/cases/*/validate",
                "/casos/cases/*/validate/**")
                .map(insensitive::parse).toList();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = normalize(request.getURI().getPath());

        if (HttpMethod.POST.equals(request.getMethod()) && matches(blockedPaths, path)) {
            return reject(exchange, HttpStatus.FORBIDDEN, "forbidden", "Ruta de uso interno");
        }

        ServerHttpRequest.Builder builder = request.mutate().headers(headers -> {
            headers.remove(USER_ID_HEADER);
            headers.remove(ROLES_HEADER);
            headers.remove(GATEWAY_SECRET_HEADER);
            if (!gatewaySecret.isBlank()) {
                headers.add(GATEWAY_SECRET_HEADER, gatewaySecret);
            }
        });

        if (HttpMethod.OPTIONS.equals(request.getMethod()) || matches(publicPaths, path)) {
            return chain.filter(exchange.mutate().request(builder.build()).build());
        }

        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")
                || authorization.substring(7).isBlank()) {
            return rejectUnauthorized(exchange, "Falta un bearer token válido");
        }

        return tokenValidator.validate(authorization.substring(7).trim())
                .flatMap(identity -> {
                    builder.header(USER_ID_HEADER, identity.subject())
                            .header(ROLES_HEADER, identity.rolesHeader());
                    return chain.filter(exchange.mutate().request(builder.build()).build());
                })
                .onErrorResume(JwksUnavailableException.class,
                        error -> reject(exchange, HttpStatus.SERVICE_UNAVAILABLE,
                                "service_unavailable", "No se pudo obtener las claves de autenticación"))
                .onErrorResume(InvalidKeycloakTokenException.class,
                        error -> rejectUnauthorized(exchange, "Token inválido o no autorizado"));
    }

    private static String normalize(String path) {
        return StringUtils.cleanPath(path.replaceAll("/{2,}", "/"));
    }

    private static boolean matches(List<PathPattern> patterns, String path) {
        PathContainer container = PathContainer.parsePath(path);
        return patterns.stream().anyMatch(pattern -> pattern.matches(container));
    }

    private Mono<Void> rejectUnauthorized(ServerWebExchange exchange, String message) {
        exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        return reject(exchange, HttpStatus.UNAUTHORIZED, "unauthorized", message);
    }

    private Mono<Void> reject(ServerWebExchange exchange, HttpStatus status, String error, String message) {
        var response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = ("{\"status\":" + status.value()
                + ",\"error\":\"" + error
                + "\",\"message\":\"" + message + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
