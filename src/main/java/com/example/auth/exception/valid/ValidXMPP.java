package com.example.auth.exception.valid;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = JabberValidator.class)
public @interface ValidXMPP {
    String message();
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
