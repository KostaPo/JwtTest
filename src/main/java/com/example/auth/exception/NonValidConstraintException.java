package com.example.auth.exception;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import java.util.ArrayList;
import java.util.List;

@Data
@RequiredArgsConstructor
public class NonValidConstraintException {

    private final List<Violation> violations;

    public NonValidConstraintException(BindingResult bindingResult) {
        this.violations = new ArrayList<>();
        for (FieldError error : bindingResult.getFieldErrors()) {
            this.violations.add(new Violation(error.getField(), error.getDefaultMessage()));
        }
    }

    @Data
    @RequiredArgsConstructor
    public static class Violation {
        private final String fieldName;
        private final String message;
    }
}