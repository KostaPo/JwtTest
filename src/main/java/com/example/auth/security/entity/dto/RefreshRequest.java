package com.example.auth.security.entity.dto;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
}
