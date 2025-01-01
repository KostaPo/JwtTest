package com.example.auth.exception.valid;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class JabberValidator implements ConstraintValidator<ValidXMPP, String> {

    private static final String LOGIN_REGEX = "^[a-zA-Z0-9._-]{1,64}$";
    private static final String SERVER_NAME_REGEX = "^[a-zA-Z0-9.-]{1,64}$";
    private static final String DOMAIN_REGEX = "^[a-zA-Z]{2,}$";

    @Override
    public boolean isValid(String jabber, ConstraintValidatorContext context) {
        if (jabber == null || jabber.trim().isEmpty()) {
            return false;
        }

        String[] parts = jabber.split("@");
        if (parts.length != 2) {
            return false;
        }

        String login = parts[0];
        String serverAndDomain = parts[1];

        if (!login.matches(LOGIN_REGEX)) {
            return false;
        }

        String[] serverParts = serverAndDomain.split("\\.");
        if (serverParts.length < 2 || !serverParts[0].matches(SERVER_NAME_REGEX)) {
            return false;
        }

        for (int i = 1; i < serverParts.length; i++) {
            if (!serverParts[i].matches(DOMAIN_REGEX)) {
                return false;
            }
        }

        return true;
    }
}
