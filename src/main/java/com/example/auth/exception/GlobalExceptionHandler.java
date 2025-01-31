package com.example.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<NonValidConstraintException> NonValidConstraintException(MethodArgumentNotValidException ex) {
        NonValidConstraintException validationError = new NonValidConstraintException(ex.getBindingResult());
        log.info("NonValidConstraintException: " + validationError);
        return new ResponseEntity<>(validationError, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NonUniqConstraintException.class)
    public ResponseEntity<ApiResponse> handleNonUniqConstraintException(NonUniqConstraintException ex) {
        ApiResponse response = new ApiResponse(ex.getMessage());
        log.info("NonValidConstraintException: " + ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponse> handleUserNotFoundException(UserNotFoundException ex) {
        ApiResponse response = new ApiResponse(ex.getMessage());
        log.info("UserNotFoundException: " + ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(TokenNotFoundException.class)
    public ResponseEntity<ApiResponse> handleTokenNotFoundException(TokenNotFoundException ex) {
        ApiResponse response = new ApiResponse(ex.getMessage());
        log.info("TokenNotFoundException: " + ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }
}
