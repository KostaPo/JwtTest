package com.example.auth.entity.dto;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
}
