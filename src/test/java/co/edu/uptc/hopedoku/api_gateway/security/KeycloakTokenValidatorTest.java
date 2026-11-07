package co.edu.uptc.hopedoku.api_gateway.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeycloakTokenValidatorTest {

    private static final String ISSUER = "http://localhost:8180/realms/hopedoku";
    private static final String CLIENT_ID = "hopedoku-godot";
    private static final String SUBJECT = "603fba8d-bb2c-4994-bc27-e9c40e30fec8";

    private RSAKey rsaKey;
    private NimbusJwtEncoder encoder;
    private KeycloakTokenValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        rsaKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
        encoder = new NimbusJwtEncoder(new ImmutableJWKSet<SecurityContext>(new JWKSet(rsaKey)));

        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
        OAuth2TokenValidator<Jwt> requiredExpiration = jwt -> jwt.getExpiresAt() != null
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Missing exp claim", null));
        JwtTimestampValidator timestampValidator = new JwtTimestampValidator(Duration.ZERO);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new JwtIssuerValidator(ISSUER), timestampValidator, requiredExpiration));
        validator = new KeycloakTokenValidator(decoder, CLIENT_ID);
    }

    @Test
    void acceptsRs256AccessTokenAndOnlyPropagatesUserAndAdminRoles() {
        AuthenticatedIdentity identity = validator.validate(token(
                ISSUER, Instant.now().plusSeconds(60), SUBJECT, "Bearer", CLIENT_ID,
                List.of("default-roles-hopedoku", "USER", "offline_access", "ADMIN", "uma_authorization")))
                .block();

        assertEquals(SUBJECT, identity.subject());
        assertEquals(List.of("USER", "ADMIN"), identity.roles());
        assertEquals("USER,ADMIN", identity.rolesHeader());
    }

    @Test
    void rejectsInvalidSignature() {
        String token = token(ISSUER, Instant.now().plusSeconds(60), SUBJECT, "Bearer", CLIENT_ID, List.of("USER"));
        String[] pieces = token.split("\\.");
        char first = pieces[2].charAt(0);
        pieces[2] = (first == 'A' ? "B" : "A") + pieces[2].substring(1);
        assertInvalid(String.join(".", pieces));
    }

    @Test
    void rejectsDifferentIssuer() {
        assertInvalid(token("https://attacker.invalid/realms/hopedoku", Instant.now().plusSeconds(60),
                SUBJECT, "Bearer", CLIENT_ID, List.of("USER")));
    }

    @Test
    void rejectsExpiredToken() {
        assertInvalid(token(ISSUER, Instant.now().minusSeconds(30), SUBJECT, "Bearer", CLIENT_ID, List.of("USER")));
    }

    @Test
    void rejectsMissingSubject() {
        assertInvalid(token(ISSUER, Instant.now().plusSeconds(60), null, "Bearer", CLIENT_ID, List.of("USER")));
    }

    @Test
    void rejectsMissingRoles() {
        assertInvalid(token(ISSUER, Instant.now().plusSeconds(60), SUBJECT, "Bearer", CLIENT_ID, null));
    }

    @Test
    void rejectsNonBearerTyp() {
        assertInvalid(token(ISSUER, Instant.now().plusSeconds(60), SUBJECT, "ID", CLIENT_ID, List.of("USER")));
    }

    @Test
    void rejectsDifferentAuthorizedParty() {
        assertInvalid(token(ISSUER, Instant.now().plusSeconds(60), SUBJECT, "Bearer", "another-client", List.of("USER")));
    }

    @Test
    void rejectsHs256TokenSignedWithArbitrarySecret() throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .issueTime(Date.from(now.minusSeconds(1)))
                .expirationTime(Date.from(now.plusSeconds(60)))
                .claim("typ", "Bearer")
                .claim("azp", CLIENT_ID)
                .claim("realm_access", Map.of("roles", List.of("USER")))
                .build();
        SignedJWT hs256 = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        hs256.sign(new MACSigner("arbitrary-test-hs256-secret-that-is-not-keycloak".getBytes(StandardCharsets.UTF_8)));
        assertInvalid(hs256.serialize());
    }

    private void assertInvalid(String compactToken) {
        assertThrows(RuntimeException.class, () -> validator.validate(compactToken).block());
    }

    private String token(String issuer, Instant expiresAt, String subject, String typ, String authorizedParty,
            List<String> roles) {
        Instant now = Instant.now();
        Instant issuedAt = expiresAt.isBefore(now) ? expiresAt.minusSeconds(60) : now.minusSeconds(1);
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("typ", typ)
                .claim("azp", authorizedParty);
        if (subject != null) {
            claims.subject(subject);
        }
        if (roles != null) {
            claims.claim("realm_access", Map.of("roles", roles));
        }
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(rsaKey.getKeyID()).build();
        return encoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
    }
}
