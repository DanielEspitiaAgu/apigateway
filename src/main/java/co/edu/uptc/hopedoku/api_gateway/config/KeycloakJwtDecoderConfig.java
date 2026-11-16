package co.edu.uptc.hopedoku.api_gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class KeycloakJwtDecoderConfig {

    @Bean
    ReactiveJwtDecoder keycloakJwtDecoder(
            @Value("${keycloak.issuer-uri}") String issuerUri,
            @Value("${keycloak.jwks-uri}") String jwksUri,
            @Value("${keycloak.audience}") String audience,
            @Value("${keycloak.allowed-azp}") String allowedAzp) {
        Set<String> allowedParties = Arrays.stream(allowedAzp.split(","))
                .map(String::trim)
                .filter(party -> !party.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
        if (allowedParties.isEmpty()) {
            throw new IllegalStateException("KEYCLOAK_ALLOWED_AZP debe incluir al menos un cliente");
        }

        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwksUri)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(jwtValidator(issuerUri, audience, allowedParties));
        return decoder;
    }

    static OAuth2TokenValidator<Jwt> jwtValidator(
            String issuerUri,
            String audience,
            Set<String> allowedParties) {
        OAuth2TokenValidator<Jwt> audienceValidator = jwt -> jwt.getAudience().contains(audience)
                ? OAuth2TokenValidatorResult.success()
                : invalidToken("El token no está destinado a este gateway");
        OAuth2TokenValidator<Jwt> authorizedPartyValidator = jwt -> allowedParties
                .contains(jwt.getClaimAsString("azp"))
                ? OAuth2TokenValidatorResult.success()
                : invalidToken("El cliente OIDC no está autorizado");

        return new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuerUri),
                audienceValidator,
                authorizedPartyValidator);
    }

    private static OAuth2TokenValidatorResult invalidToken(String description) {
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error("invalid_token", description, null));
    }
}
