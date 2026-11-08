package co.edu.uptc.hopedoku.api_gateway.security;

public class JwksUnavailableException extends RuntimeException {

    public JwksUnavailableException(Throwable cause) {
        super("Keycloak JWKS is unavailable", cause);
    }
}
