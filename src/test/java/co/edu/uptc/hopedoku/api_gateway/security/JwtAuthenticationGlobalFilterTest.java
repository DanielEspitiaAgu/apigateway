package co.edu.uptc.hopedoku.api_gateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationGlobalFilterTest {

    private static final String GATEWAY_SECRET = "test-gateway-secret";
    private ReactiveJwtDecoder jwtDecoder;
    private JwtAuthenticationGlobalFilter filter;

    @BeforeEach
    void setUp() {
        jwtDecoder = mock(ReactiveJwtDecoder.class);
        filter = new JwtAuthenticationGlobalFilter(jwtDecoder, GATEWAY_SECRET);
    }

    @Test
    void rejectsRequestsWithoutBearerToken() {
        MockServerWebExchange exchange = exchange("GET", "/usuarios/users/me");

        filter.filter(exchange, ignored -> Mono.empty()).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void rejectsInvalidBearerToken() {
        when(jwtDecoder.decode("invalid")).thenReturn(Mono.error(new JwtException("invalid")));
        MockServerWebExchange exchange = exchange("GET", "/usuarios/users/me", "Bearer invalid");

        filter.filter(exchange, ignored -> Mono.empty()).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void requiresGatewaySecretAtConstruction() {
        assertThrows(IllegalStateException.class,
                () -> new JwtAuthenticationGlobalFilter(jwtDecoder, " "));
    }

    @Test
    void rewritesIdentityRolesAndGatewaySecretFromValidatedJwt() {
        when(jwtDecoder.decode("valid")).thenReturn(Mono.just(jwt("subject-1", List.of("USER"))));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/partidas/matches/history/me")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer valid")
                        .header("X-User-Id", "spoofed")
                        .header("X-Roles", "ADMIN")
                        .header("X-Gateway-Secret", "spoofed")
                        .header("X-Internal-Token", "spoofed")
                        .build());
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
        GatewayFilterChain chain = request -> {
            forwarded.set(request);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        var headers = forwarded.get().getRequest().getHeaders();
        assertEquals("subject-1", headers.getFirst("X-User-Id"));
        assertEquals("USER", headers.getFirst("X-Roles"));
        assertEquals(GATEWAY_SECRET, headers.getFirst("X-Gateway-Secret"));
        assertNull(headers.getFirst("X-Internal-Token"));
        assertNull(headers.getFirst(HttpHeaders.AUTHORIZATION));
    }

    @Test
    void allowsSelectedPublicDocumentationWithoutForwardingClientIdentity() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/casos/docs-json")
                        .header("X-User-Id", "spoofed")
                        .header("X-Roles", "ADMIN")
                        .header("X-Gateway-Secret", "spoofed")
                        .build());
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, request -> {
            forwarded.set(request);
            return Mono.empty();
        }).block();

        assertNotNull(forwarded.get());
        var headers = forwarded.get().getRequest().getHeaders();
        assertNull(headers.getFirst("X-User-Id"));
        assertNull(headers.getFirst("X-Roles"));
        assertEquals(GATEWAY_SECRET, headers.getFirst("X-Gateway-Secret"));
    }

    @Test
    void requiresAdminRoleForAdminCasesAndAllowsUserRoleForPlayerRoutes() {
        when(jwtDecoder.decode("user")).thenReturn(Mono.just(jwt("user-1", List.of("USER"))));
        MockServerWebExchange adminRequest = exchange("POST", "/casos/admin/cases", "Bearer user");
        filter.filter(adminRequest, ignored -> Mono.empty()).block();
        assertEquals(HttpStatus.FORBIDDEN, adminRequest.getResponse().getStatusCode());

        MockServerWebExchange playerRequest = exchange("GET", "/casos/cases", "Bearer user");
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
        filter.filter(playerRequest, request -> {
            forwarded.set(request);
            return Mono.empty();
        }).block();
        assertNotNull(forwarded.get());
    }

    @Test
    void allowsAdminRoleForAdminCases() {
        when(jwtDecoder.decode("admin")).thenReturn(Mono.just(jwt("admin-1", List.of("USER", "ADMIN"))));
        MockServerWebExchange exchange = exchange("POST", "/casos/admin/cases", "Bearer admin");
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, request -> {
            forwarded.set(request);
            return Mono.empty();
        }).block();

        assertNotNull(forwarded.get());
        assertEquals("ADMIN,USER", forwarded.get().getRequest().getHeaders().getFirst("X-Roles"));
    }

    @Test
    void rejectsTokensWithoutFunctionalRoles() {
        when(jwtDecoder.decode("roleless")).thenReturn(Mono.just(jwt("user-1", List.of())));
        MockServerWebExchange exchange = exchange("GET", "/partidas/matches/ranking", "Bearer roleless");

        filter.filter(exchange, ignored -> Mono.empty()).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
    }

    @Test
    void blocksInternalResultsAndCaseValidationRoutesBeforeProxying() {
        for (String path : List.of(
                "/usuarios/users/user-1/results",
                "/casos/cases/case-1/validate")) {
            MockServerWebExchange exchange = exchange("POST", path);
            filter.filter(exchange, ignored -> Mono.empty()).block();
            assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        }
    }

    private static MockServerWebExchange exchange(String method, String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.method(
                org.springframework.http.HttpMethod.valueOf(method), path).build());
    }

    private static MockServerWebExchange exchange(String method, String path, String authorization) {
        return MockServerWebExchange.from(MockServerHttpRequest.method(
                        org.springframework.http.HttpMethod.valueOf(method), path)
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .build());
    }

    private static Jwt jwt(String subject, List<String> roles) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("validated")
                .header("alg", "RS256")
                .claim("sub", subject)
                .claim("realm_access", Map.of("roles", roles))
                .issuedAt(now.minusSeconds(1))
                .expiresAt(now.plusSeconds(300))
                .build();
    }
}
