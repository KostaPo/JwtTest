package com.example.auth.config;

import com.example.auth.exception.TokenNotFoundException;
import com.example.auth.service.JwtService;
import com.example.auth.service.RefreshTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.Optional;

@Slf4j
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    private final JwtService jwtService;
    private final RefreshTokenService tokenService;

    public CustomLogoutSuccessHandler(@Lazy RefreshTokenService tokenService, JwtService jwtService) {
        this.tokenService = tokenService;
        this.jwtService = jwtService;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException {

        Cookie[] cookies = request.getCookies();
        Optional<String> token = Arrays.stream(cookies != null ? cookies : new Cookie[0])
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst();

        String rToken = token.orElseThrow(() -> new TokenNotFoundException("Refresh token not found"));
        String username;

        try {
            username = jwtService.getUsername(rToken);
        } catch (ExpiredJwtException e) {
            username = e.getClaims().getSubject();
            log.warn("Expired JWT token for user [{}] during logout", username);
        } catch (JwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            throw new TokenNotFoundException("Invalid token");
        }

        if (username == null || username.trim().isEmpty()) {
            throw new TokenNotFoundException("Username not found in token");
        }

        tokenService.removeRefreshTokenByUsername(username);

        Cookie cookie = new Cookie("refresh_token", null);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("Logout successful");

        log.info("User [{}] logged out", username);
    }
}
