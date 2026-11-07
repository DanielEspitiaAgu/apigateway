package co.edu.uptc.hopedoku.api_gateway.security;

public class InvalidKeycloakTokenException extends RuntimeException {

    public InvalidKeycloakTokenException() {
        super("Invalid Keycloak access token");
    }

    public InvalidKeycloakTokenException(Throwable cause) {
        super("Invalid Keycloak access token", cause);
    }
}
