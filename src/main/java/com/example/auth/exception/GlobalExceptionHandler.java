package com.example.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<NonValidConstraintException> NonValidConstraintException(MethodArgumentNotValidException ex) {
        NonValidConstraintException validationError = new NonValidConstraintException(ex.getBindingResult());
        return new ResponseEntity<>(validationError, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NonUniqConstraintException.class)
    public ResponseEntity<ApiResponse> handleNonUniqConstraintException(NonUniqConstraintException ex) {
        ApiResponse response = new ApiResponse(HttpStatus.CONFLICT.value(), ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }
}
