package com.example.auth.exception;

import lombok.Getter;

@Getter
public class TokenNotFoundException extends RuntimeException {
    public TokenNotFoundException(String message) {
        super(message);
    }
}
