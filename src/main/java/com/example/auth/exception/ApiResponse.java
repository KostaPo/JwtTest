package com.example.auth.exception;

import lombok.Data;

import java.util.Date;

@Data
public class ApiResponse {
    private String message;
    private Date timestamp;

    public ApiResponse(String message) {
        this.message = message;
        this.timestamp = new Date();
    }
}
