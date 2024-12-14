package com.example.auth.entity.dto;

import lombok.Data;
import org.springframework.http.HttpStatusCode;

import java.util.Date;

@Data
public class FaultResponse {
    private Integer status;
    private String message;
    private Date timestamp;

    public FaultResponse(Integer status, String message) {
        this.status = status;
        this.message = message;
        this.timestamp = new Date();
    }
}
