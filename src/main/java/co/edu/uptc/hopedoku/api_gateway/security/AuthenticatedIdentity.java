package co.edu.uptc.hopedoku.api_gateway.security;

import java.util.List;

public record AuthenticatedIdentity(String subject, List<String> roles) {

    public AuthenticatedIdentity {
        roles = List.copyOf(roles);
    }

    public String rolesHeader() {
        return String.join(",", roles);
    }
}
