package com.example.auth.security.controller;

import com.example.auth.security.entity.dto.AuthRequest;
import com.example.auth.security.entity.dto.AuthResponse;
import com.example.auth.user.entity.dto.RegistrationRequest;
import com.example.auth.exception.ApiResponse;
import com.example.auth.exception.NonUniqConstraintException;
import com.example.auth.user.AppUserService;
import com.example.auth.security.jwt.JwtService;
import com.example.auth.security.jwt.RefreshTokenService;
import com.example.auth.security.service.UserSecurityService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping({"api/v2/auth"})
public class AuthController {

    @Value("${jwt.access-token-ttl}")
    private Duration accessTokenLifeTime;

    @Value("${jwt.refresh-token-ttl}")
    private Duration refreshTokenLifeTime;

    @Value("${jwt.remember-me-ttl}")
    private Duration rememberMeLifeTime;

    private final JwtService jwtService;
    private final UserSecurityService userSecurityService;
    private final AppUserService appUserService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest,
                                                HttpServletResponse response) {

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authRequest.getUsername(),
                    authRequest.getPassword())
            );
        } catch (BadCredentialsException ex) {
            return new ResponseEntity<>(new ApiResponse("Bad login or password!"), HttpStatus.BAD_REQUEST);
        }

        UserDetails userDetails = userSecurityService.loadUserByUsername(authRequest.getUsername());

        Duration refreshDuration = authRequest.getRememberMe() ? rememberMeLifeTime : refreshTokenLifeTime;

        String accessToken = jwtService.generateToken(userDetails, accessTokenLifeTime);
        String refreshToken = jwtService.generateToken(userDetails, refreshDuration);

        refreshTokenService.saveToken(refreshToken);

        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 * 24);

        response.addCookie(cookie);

        return ResponseEntity.ok(new AuthResponse(accessToken, authRequest.getUsername()));
    }


    @PostMapping("/registration")
    public ResponseEntity<?> registration(@Valid @RequestBody RegistrationRequest registrationRequest) {
        try {
            log.info("registration request: " + registrationRequest);
            appUserService.save(registrationRequest);
        } catch (DataIntegrityViolationException e) {
            throw new NonUniqConstraintException("This username already exist!");
        }

        return ResponseEntity.ok(new ApiResponse("User registered successfully!"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(value = "refresh_token", required = false) String refreshToken) {
        log.info("TOKEN REFRESH REQUEST");
        if(refreshToken != null) {
            try{
                String username = jwtService.getUsername(refreshToken);
                String oldRefreshToken = refreshTokenService.getTokenByUsername(username);
                if(refreshTokenService.isTokenEquals(refreshToken, oldRefreshToken)) {
                    UserDetails userDetails = userSecurityService.loadUserByUsername(username);
                    String newAccessToken = jwtService.generateToken(userDetails, accessTokenLifeTime);
                    log.info("user [{}] get new access token", username);
                    return ResponseEntity.ok(new AuthResponse(newAccessToken, username));
                } else {
                    log.info("user [{}] provided wrong refresh token", username);
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bad refresh token");
                }
            } catch (JwtException ex) {
                log.info("user provided expired refresh token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bad refresh token");
            }
        }
        log.info("user provided expired refresh token");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bad refresh token");
    }
}
