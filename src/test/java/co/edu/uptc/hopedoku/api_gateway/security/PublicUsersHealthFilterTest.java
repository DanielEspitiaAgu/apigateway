package co.edu.uptc.hopedoku.api_gateway.security;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

class PublicUsersHealthFilterTest {

    @Test
    void allowsHealthWithoutBearerAndStripsClientIdentityHeaders() {
        JwtAuthenticationGlobalFilter filter = new JwtAuthenticationGlobalFilter(
                mock(KeycloakTokenValidator.class), "test-gateway-secret");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/usuarios/health")
                        .header("X-User-Id", "spoofed")
                        .header("X-Roles", "ADMIN")
                        .header("X-Gateway-Secret", "spoofed")
                        .build());
        AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
        GatewayFilterChain chain = request -> {
            forwarded.set(request);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertNotNull(forwarded.get());
        var headers = forwarded.get().getRequest().getHeaders();
        assertNull(headers.getFirst("X-User-Id"));
        assertNull(headers.getFirst("X-Roles"));
        assertEquals("test-gateway-secret", headers.getFirst("X-Gateway-Secret"));
    }
}
