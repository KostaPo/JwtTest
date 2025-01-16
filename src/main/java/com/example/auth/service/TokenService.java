package com.example.auth.service;

public interface TokenService {
    String getTokenByUsername(String username);
    void saveToken(String rToken);
    boolean isTokenEquals(String sourceToken, String encryptedToken);
    void removeRefreshTokenByUsername(String username);
}