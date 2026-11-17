package co.edu.uptc.hopedoku.api_gateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationGlobalFilterTest {

    private static final String GATEWAY_SECRET = "test-gateway-secret";
    private KeycloakTokenValidator tokenValidator;
    private JwtAuthenticationGlobalFilter filter;

    @BeforeEach
    void setUp() {
        tokenValidator = mock(KeycloakTokenValidator.class);
        filter = new JwtAuthenticationGlobalFilter(tokenValidator, GATEWAY_SECRET);
    }

    @Test
    void rejectsRequestsWithoutBearerToken() {
        MockServerWebExchange exchange = exchange("GET", "/usuarios/users/me");

        filter.filter(exchange, ignored -> Mono.empty()).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void rejectsInvalidBearerToken() {
        when(tokenValidator.validate("invalid")).thenReturn(Mono.error(new InvalidKeycloakTokenException()));
        MockServerWebExchange exchange = exchange("GET", "/usuarios/users/me", "Bearer invalid");

        filter.filter(exchange, ignored -> Mono.empty()).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
    }

    @Test
    void rewritesIdentityRolesAndGatewaySecretFromValidatedJwt() {
        when(tokenValidator.validate("valid"))
                .thenReturn(Mono.just(new AuthenticatedIdentity("subject-1", List.of("USER"))));
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
        when(tokenValidator.validate("user"))
                .thenReturn(Mono.just(new AuthenticatedIdentity("user-1", List.of("USER"))));
        MockServerWebExchange adminRequest = exchange("POST", "/casos/admin/cases", "Bearer user");
        AtomicReference<ServerWebExchange> adminForwarded = new AtomicReference<>();
        filter.filter(adminRequest, request -> {
            adminForwarded.set(request);
            return Mono.empty();
        }).block();
        assertNotNull(adminForwarded.get());
        assertEquals("USER", adminForwarded.get().getRequest().getHeaders().getFirst("X-Roles"));

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
        when(tokenValidator.validate("admin"))
                .thenReturn(Mono.just(new AuthenticatedIdentity("admin-1", List.of("USER", "ADMIN"))));
        MockServerWebExchange exchange = exchange("POST", "/casos/admin/cases", "Bearer admin");
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, request -> {
            forwarded.set(request);
            return Mono.empty();
        }).block();

        assertNotNull(forwarded.get());
        assertEquals("USER,ADMIN", forwarded.get().getRequest().getHeaders().getFirst("X-Roles"));
    }

    @Test
    void rejectsTokensWithoutFunctionalRoles() {
        when(tokenValidator.validate("roleless"))
                .thenReturn(Mono.error(new InvalidKeycloakTokenException()));
        MockServerWebExchange exchange = exchange("GET", "/partidas/matches/ranking", "Bearer roleless");

        filter.filter(exchange, ignored -> Mono.empty()).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
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

}
