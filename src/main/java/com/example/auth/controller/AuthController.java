package com.example.auth.controller;

import com.example.auth.entity.dto.AuthRequest;
import com.example.auth.entity.dto.AuthResponse;
import com.example.auth.exception.ApiResponse;
import com.example.auth.exception.NonUniqConstraintException;
import com.example.auth.service.AppUserService;
import com.example.auth.service.JwtService;
import com.example.auth.service.UserSecService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.time.Duration;

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
    private final UserSecService userSecService;
    private final AppUserService appUserService;
    private final AuthenticationManager authenticationManager;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authRequest.getUsername(),
                    authRequest.getPassword())
            );
        } catch (BadCredentialsException ex) {
            return new ResponseEntity<>(
                    new ApiResponse(HttpStatus.UNAUTHORIZED.value(), "Bad login or password!"),
                    HttpStatus.UNAUTHORIZED
            );
        }
        UserDetails userDetails = userSecService.loadUserByUsername(authRequest.getUsername());
        String accessToken = jwtService.generateToken(userDetails, accessTokenLifeTime);
        String refreshToken = jwtService.generateToken(userDetails, authRequest.getRememberMe() != null
                                                                    ? rememberMeLifeTime
                                                                    : refreshTokenLifeTime);
        return ResponseEntity.ok(AuthResponse.builder()
                                            .accessToken(accessToken)
                                            .refreshToken(refreshToken)
                                            .build()
        );
    }


    @PostMapping("/registration")
    public ResponseEntity<?> registration(@Valid @RequestBody AuthRequest authRequest) {
        try {
            appUserService.save(authRequest);
        } catch (DataIntegrityViolationException e) {
            throw new NonUniqConstraintException("This username already exist!");
        }

        return ResponseEntity.ok(new ApiResponse(HttpStatus.CREATED.value(), "User registered successfully!"));
    }
}
