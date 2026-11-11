package co.edu.uptc.hopedoku.api_gateway.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class JwtAuthenticationGlobalFilterTest {

    private KeycloakTokenValidator tokenValidator;
    private JwtAuthenticationGlobalFilter filter;

    @BeforeEach
    void setUp() {
        tokenValidator = mock(KeycloakTokenValidator.class);
        filter = new JwtAuthenticationGlobalFilter(tokenValidator, "test-gateway-secret");
    }

    @Test
    void blocksDirectValidationWithoutAuthentication() {
        assertBlocked("/casos/cases/abc123/validate", null);
        verifyNoInteractions(tokenValidator);
    }

    @Test
    void blocksDirectValidationEvenWithBearerToken() {
        assertBlocked("/casos/cases/abc123/validate", "Bearer valid-looking-token");
        verifyNoInteractions(tokenValidator);
    }

    @Test
    void blocksCaseVariantsTrailingSlashDuplicateSlashAndSubpaths() {
        assertBlocked("/CASOS/cases/abc123/VALIDATE", null);
        assertBlocked("/casos//cases/abc123/validate/", null);
        assertBlocked("/casos/cases/abc123/validate/extra", null);
        assertBlocked("/casos/cases/abc123/%76alidate", null);
    }

    @Test
    void keepsCaseReadRoutesAvailableToAuthenticatedUsers() {
        AuthenticatedIdentity identity = new AuthenticatedIdentity("opaque-user-id", List.of("USER"));
        when(tokenValidator.validate("valid-looking-token")).thenReturn(Mono.just(identity));

        for (String path : List.of(
                "/casos/cases",
                "/casos/cases/abc123",
                "/casos/cases/abc123/hints?level=1")) {
            AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
            MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                    .method(HttpMethod.GET, path)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer valid-looking-token")
                    .header("X-User-Id", "spoofed")
                    .header("X-Roles", "ADMIN")
                    .header("X-Gateway-Secret", "spoofed")
                    .build());

            filter.filter(exchange, next(forwarded)).block();

            assertNotNull(forwarded.get(), "Expected route to continue: " + path);
            assertEquals("opaque-user-id", forwarded.get().getRequest().getHeaders().getFirst("X-User-Id"));
            assertEquals("USER", forwarded.get().getRequest().getHeaders().getFirst("X-Roles"));
            assertEquals("test-gateway-secret",
                    forwarded.get().getRequest().getHeaders().getFirst("X-Gateway-Secret"));
        }
    }

    private void assertBlocked(String path, String authorization) {
        MockServerHttpRequest.BodyBuilder request = MockServerHttpRequest.post(path);
        if (authorization != null) {
            request.header(HttpHeaders.AUTHORIZATION, authorization);
        }
        MockServerWebExchange exchange = MockServerWebExchange.from(request.build());
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();

        filter.filter(exchange, next(forwarded)).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        assertNull(forwarded.get(), "Blocked request reached downstream: " + path);
    }

    private static org.springframework.cloud.gateway.filter.GatewayFilterChain next(
            AtomicReference<ServerWebExchange> forwarded) {
        return exchange -> {
            forwarded.set(exchange);
            return Mono.empty();
        };
    }
}
