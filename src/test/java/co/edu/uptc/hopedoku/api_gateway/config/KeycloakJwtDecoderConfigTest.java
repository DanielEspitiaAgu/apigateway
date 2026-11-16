package co.edu.uptc.hopedoku.api_gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeycloakJwtDecoderConfigTest {

    private static final String ISSUER = "http://localhost:8180/realms/hopedoku";
    private static final String AUDIENCE = "hopedoku-gateway";
    private static final Set<String> ALLOWED_PARTIES = Set.of("hopedoku-godot", "hopedoku-test");

    @Test
    void acceptsOnlyCurrentKeycloakTokensIntendedForThisGatewayAndClient() {
        OAuth2TokenValidator<Jwt> validator = validator();

        assertFalse(validator.validate(jwt(ISSUER, List.of(AUDIENCE), "hopedoku-test", Instant.now()))
                .hasErrors());
        assertTrue(validator.validate(jwt(ISSUER, List.of("other-service"), "hopedoku-test", Instant.now()))
                .hasErrors());
        assertTrue(validator.validate(jwt(ISSUER, List.of(AUDIENCE), "unknown-client", Instant.now()))
                .hasErrors());
        assertTrue(validator.validate(jwt("http://other/realm", List.of(AUDIENCE),
                "hopedoku-test", Instant.now())).hasErrors());
        assertTrue(validator.validate(jwt(ISSUER, List.of(AUDIENCE), "hopedoku-test",
                Instant.now().minusSeconds(600))).hasErrors());
    }

    private static OAuth2TokenValidator<Jwt> validator() {
        return KeycloakJwtDecoderConfig.jwtValidator(ISSUER, AUDIENCE, ALLOWED_PARTIES);
    }

    private static Jwt jwt(String issuer, List<String> audiences, String authorizedParty, Instant now) {
        return Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .issuer(issuer)
                .subject("user-1")
                .audience(audiences)
                .claim("azp", authorizedParty)
                .issuedAt(now.minusSeconds(600))
                .expiresAt(now.plusSeconds(300))
                .build();
    }
}
