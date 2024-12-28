package com.example.auth.exception;

import lombok.Getter;

@Getter
public class NonUniqConstraintException extends RuntimeException {

    public NonUniqConstraintException(String message) {
        super(message);
    }
}
