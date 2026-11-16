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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    private static final String USER_ID_HEADER = "X-User-Id";
    private static final String ROLES_HEADER = "X-Roles";
    private static final String GATEWAY_SECRET_HEADER = "X-Gateway-Secret";
    private static final Pattern USER_ID_PATTERN = Pattern.compile("[A-Za-z0-9-]{1,64}");
    private static final Set<String> PLAYER_ROLES = Set.of("USER", "ADMIN");

    private final ReactiveJwtDecoder jwtDecoder;
    private final String gatewaySecret;
    private final List<PathPattern> publicPaths;
    private final List<PathPattern> internalPaths;
    private final List<PathPattern> adminPaths;

    public JwtAuthenticationGlobalFilter(
            ReactiveJwtDecoder jwtDecoder,
            @Value("${gateway.secret}") String gatewaySecret) {
        if (!StringUtils.hasText(gatewaySecret)) {
            throw new IllegalStateException("GATEWAY_SECRET debe estar configurado");
        }
        this.jwtDecoder = jwtDecoder;
        this.gatewaySecret = gatewaySecret;

        PathPatternParser parser = PathPatternParser.defaultInstance;
        this.publicPaths = Stream.of(
                "/usuarios/health",
                "/usuarios/swagger-ui/**", "/usuarios/swagger-ui.html", "/usuarios/v3/api-docs/**",
                "/casos/health", "/casos/docs/**", "/casos/docs-json",
                "/partidas/health", "/partidas/docs/**", "/partidas/redoc", "/partidas/openapi.json")
                .map(parser::parse).toList();
        this.internalPaths = Stream.of(
                "/usuarios/users/*/results/**",
                "/casos/cases/*/validate")
                .map(parser::parse).toList();
        this.adminPaths = List.of(parser.parse("/casos/admin/cases/**"));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = normalize(request.getURI().getPath());

        if (matches(internalPaths, path)) {
            return reject(exchange, HttpStatus.FORBIDDEN, "Ruta de uso interno");
        }

        ServerHttpRequest.Builder builder = request.mutate().headers(headers -> {
            headers.remove(USER_ID_HEADER);
            headers.remove(ROLES_HEADER);
            headers.remove(GATEWAY_SECRET_HEADER);
            headers.remove("X-Internal-Token");
            headers.remove(HttpHeaders.AUTHORIZATION);
            headers.set(GATEWAY_SECRET_HEADER, gatewaySecret);
        });

        if (HttpMethod.OPTIONS.equals(request.getMethod())
                || (HttpMethod.GET.equals(request.getMethod()) && matches(publicPaths, path))) {
            return chain.filter(exchange.mutate().request(builder.build()).build());
        }

        String token = bearerToken(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
        if (token == null) {
            return reject(exchange, HttpStatus.UNAUTHORIZED, "Token ausente o inválido");
        }

        return jwtDecoder.decode(token)
                .flatMap(jwt -> authorize(exchange, chain, builder, path, jwt))
                .onErrorResume(JwtException.class,
                        error -> reject(exchange, HttpStatus.UNAUTHORIZED, "Token inválido o vencido"));
    }

    private Mono<Void> authorize(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            ServerHttpRequest.Builder builder,
            String path,
            Jwt jwt) {
        String userId = jwt.getSubject();
        Set<String> roles = userRoles(jwt);
        if (userId == null || !USER_ID_PATTERN.matcher(userId).matches()) {
            return reject(exchange, HttpStatus.UNAUTHORIZED, "Token sin identidad válida");
        }
        if (roles.isEmpty()) {
            return reject(exchange, HttpStatus.FORBIDDEN, "Se requiere rol USER o ADMIN");
        }
        if (matches(adminPaths, path) && !roles.contains("ADMIN")) {
            return reject(exchange, HttpStatus.FORBIDDEN, "Se requiere rol ADMIN");
        }

        builder.header(USER_ID_HEADER, userId)
                .header(ROLES_HEADER, String.join(",", roles));
        return chain.filter(exchange.mutate().request(builder.build()).build());
    }

    private static Set<String> userRoles(Jwt jwt) {
        Object realmAccessClaim = jwt.getClaims().get("realm_access");
        if (!(realmAccessClaim instanceof Map<?, ?> realmAccess)) {
            return Set.of();
        }
        Object rolesClaim = realmAccess.get("roles");
        if (!(rolesClaim instanceof Collection<?> claims)) {
            return Set.of();
        }
        Set<String> roles = new TreeSet<>();
        claims.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(PLAYER_ROLES::contains)
                .forEach(roles::add);
        return roles;
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || authorization.length() <= 7
                || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = authorization.substring(7).trim();
        return StringUtils.hasText(token) ? token : null;
    }

    private static String normalize(String path) {
        return StringUtils.cleanPath(path.replaceAll("/{2,}", "/"));
    }

    private static boolean matches(List<PathPattern> patterns, String path) {
        PathContainer container = PathContainer.parsePath(path);
        return patterns.stream().anyMatch(pattern -> pattern.matches(container));
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
