package co.edu.uptc.hopedoku.api_gateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;

@Component
public class KeycloakTokenValidator {

    private static final Set<String> ALLOWED_ROLES = Set.of("USER", "ADMIN");

    private final ReactiveJwtDecoder decoder;
    private final String authorizedParty;

    public KeycloakTokenValidator(
            ReactiveJwtDecoder decoder,
            @Value("${keycloak.authorized-party}") String authorizedParty) {
        this.decoder = decoder;
        this.authorizedParty = authorizedParty;
    }

    public Mono<AuthenticatedIdentity> validate(String token) {
        return decoder.decode(token)
                .onErrorMap(this::mapDecoderFailure)
                .map(this::extractIdentity);
    }

    private RuntimeException mapDecoderFailure(Throwable error) {
        if (isJwksUnavailable(error)) {
            return new JwksUnavailableException(error);
        }
        return error instanceof InvalidKeycloakTokenException
                ? (InvalidKeycloakTokenException) error
                : new InvalidKeycloakTokenException(error);
    }

    private static boolean isJwksUnavailable(Throwable error) {
        Throwable current = error;
        while (current != null) {
            if (current instanceof WebClientRequestException
                    || current instanceof ConnectException
                    || current instanceof SocketTimeoutException
                    || current instanceof UnknownHostException
                    || current instanceof TimeoutException
                    || current instanceof IOException
                    || current.getClass().getName().contains("RemoteKeySourceException")) {
                return true;
            }
            if (current instanceof WebClientResponseException response
                    && response.getStatusCode().is5xxServerError()) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private AuthenticatedIdentity extractIdentity(Jwt jwt) {
        if (!"Bearer".equals(jwt.getClaimAsString("typ"))
                || !authorizedParty.equals(jwt.getClaimAsString("azp"))
                || jwt.getSubject() == null || jwt.getSubject().isBlank()) {
            throw new InvalidKeycloakTokenException();
        }

        Object realmAccessClaim = jwt.getClaims().get("realm_access");
        if (!(realmAccessClaim instanceof Map<?, ?> realmAccess)) {
            throw new InvalidKeycloakTokenException();
        }
        Object rolesClaim = realmAccess.get("roles");
        if (!(rolesClaim instanceof Collection<?> roleValues)) {
            throw new InvalidKeycloakTokenException();
        }

        List<String> roles = new ArrayList<>();
        for (Object role : roleValues) {
            if (role instanceof String roleName && ALLOWED_ROLES.contains(roleName) && !roles.contains(roleName)) {
                roles.add(roleName);
            }
        }
        if (roles.isEmpty()) {
            throw new InvalidKeycloakTokenException();
        }
        return new AuthenticatedIdentity(jwt.getSubject(), roles);
    }
}
