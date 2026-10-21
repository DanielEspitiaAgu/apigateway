package co.edu.uptc.hopedoku.api_gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
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

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String ROLES_HEADER = "X-Roles";
    private static final String GATEWAY_SECRET_HEADER = "X-Gateway-Secret";
    private final String gatewaySecret;

    private final SecretKey key;
    private final List<PathPattern> publicPaths;
    private final List<PathPattern> blockedPaths;

    public JwtAuthenticationGlobalFilter(@Value("${jwt.secret}") String secret,
            @Value("${gateway.secret:}") String gatewaySecret, String gatewaySecret2) {
        this.gatewaySecret = gatewaySecret;
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        PathPatternParser parser = PathPatternParser.defaultInstance;
        this.publicPaths = Stream.of(
                "/usuarios/auth/**",
                "/usuarios/swagger-ui/**", "/usuarios/swagger-ui.html", "/usuarios/v3/api-docs/**",
                "/casos/docs/**", "/casos/docs-json",
                "/partidas/docs/**", "/partidas/redoc", "/partidas/openapi.json")
                .map(parser::parse).toList();

        PathPatternParser insensitive = new PathPatternParser();
        insensitive.setCaseSensitive(false);
        this.blockedPaths = Stream.of("/usuarios/users/*/results/**")
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

        if (matches(blockedPaths, path)) {
            return reject(exchange, HttpStatus.FORBIDDEN, "Ruta de uso interno");
        }

        ServerHttpRequest.Builder builder = request.mutate().headers(h -> {
            h.remove(USER_ID_HEADER);
            h.remove(ROLES_HEADER);
            h.remove(GATEWAY_SECRET_HEADER);
            if (!gatewaySecret.isBlank()) {
                h.add(GATEWAY_SECRET_HEADER, gatewaySecret);
            }
        });

        if (HttpMethod.OPTIONS.equals(request.getMethod()) || matches(publicPaths, path)) {
            return chain.filter(exchange.mutate().request(builder.build()).build());
        }

        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return reject(exchange, HttpStatus.UNAUTHORIZED, "Token ausente");
        }

        Claims claims;
        try {
            Jws<Claims> jws = Jwts.parser().verifyWith(key).build()
                    .parseSignedClaims(authorization.substring(7));
            if (!"HS256".equals(jws.getHeader().getAlgorithm())) {
                return reject(exchange, HttpStatus.UNAUTHORIZED, "Algoritmo no permitido");
            }
            claims = jws.getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            return reject(exchange, HttpStatus.UNAUTHORIZED, "Token inválido o vencido");
        }

        String userId = claims.get("userId", String.class);
        List<?> roles = claims.get("roles", List.class);
        if (userId == null || roles == null) {
            return reject(exchange, HttpStatus.UNAUTHORIZED, "Token sin identidad: inicie sesión de nuevo");
        }

        builder.header(USER_ID_HEADER, userId)
                .header(ROLES_HEADER, roles.stream().map(String::valueOf).collect(Collectors.joining(",")));
        return chain.filter(exchange.mutate().request(builder.build()).build());
    }

    private static String normalize(String path) {
        return StringUtils.cleanPath(path.replaceAll("/{2,}", "/"));
    }

    private static boolean matches(List<PathPattern> patterns, String path) {
        PathContainer container = PathContainer.parsePath(path);
        return patterns.stream().anyMatch(p -> p.matches(container));
    }

    private Mono<Void> reject(ServerWebExchange exchange, HttpStatus status, String message) {
        var response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        if (status == HttpStatus.UNAUTHORIZED) {
            response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
        byte[] body = ("{\"status\":" + status.value() + ",\"error\":\"" + message + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}