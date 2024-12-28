package com.example.auth.exception;

import lombok.Data;

import java.util.Date;

@Data
public class ApiResponse {
    private Integer status;
    private String message;
    private Date timestamp;

    public ApiResponse(Integer status, String message) {
        this.status = status;
        this.message = message;
        this.timestamp = new Date();
    }
}
