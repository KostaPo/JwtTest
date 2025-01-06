package com.example.auth.controller;

import com.example.auth.entity.dto.AuthRequest;
import com.example.auth.entity.dto.AuthResponse;
import com.example.auth.entity.dto.RegistrationRequest;
import com.example.auth.exception.ApiResponse;
import com.example.auth.exception.NonUniqConstraintException;
import com.example.auth.service.AppUserService;
import com.example.auth.service.JwtService;
import com.example.auth.service.UserSecService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

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
    private final UserSecService userSecService;
    private final AppUserService appUserService;
    private final AuthenticationManager authenticationManager;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest,
                                                HttpServletResponse response) {

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

        Duration refreshDuration = authRequest.getRememberMe() != null ? rememberMeLifeTime : refreshTokenLifeTime;

        String accessToken = jwtService.generateToken(userDetails, accessTokenLifeTime);
        String refreshToken = jwtService.generateToken(userDetails, refreshDuration);

        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 * 24);

        response.addCookie(cookie);

        return ResponseEntity.ok(new AuthResponse(accessToken));
    }


    @PostMapping("/registration")
    public ResponseEntity<?> registration(@Valid @RequestBody RegistrationRequest registrationRequest) {
        try {
            log.info("registration request: " + registrationRequest);
            appUserService.save(registrationRequest);
        } catch (DataIntegrityViolationException e) {
            throw new NonUniqConstraintException("This username already exist!");
        }

        return ResponseEntity.ok(new ApiResponse(HttpStatus.CREATED.value(), "User registered successfully!"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(value = "refresh_token", required = false) String refreshToken) {
        if(!jwtService.isExpired(refreshToken)) {
            String username = jwtService.getUsername(refreshToken);
            UserDetails userDetails = userSecService.loadUserByUsername(username);
            String newAccessToken = jwtService.generateToken(userDetails, accessTokenLifeTime);
            log.info("user [{}] get newAccessToken", username);
            return ResponseEntity.ok(new AuthResponse(newAccessToken));
        }
        return ResponseEntity.ok("refresh");
    }
}
