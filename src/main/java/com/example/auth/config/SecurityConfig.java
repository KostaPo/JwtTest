package com.example.auth.config;

import com.example.auth.exception.ApiResponse;
import com.example.auth.service.JwtService;
import com.example.auth.service.UserSecService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final UserSecService userSecService;
    private final JwtService jwtService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/info").authenticated()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll()
                );

        http.addFilterBefore(jwtRequestFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173/"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Authorization", "Content-Type"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userSecService);
        return daoAuthenticationProvider;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public OncePerRequestFilter jwtRequestFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
                ObjectMapper objectMapper = new ObjectMapper();
                String authHeader = request.getHeader("Authorization");
                String username = null;
                String jwt = null;

                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    jwt = authHeader.substring(7);
                    try {
                        username = jwtService.getUsername(jwt);
                    } catch (MalformedJwtException ex) {
                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        response.setContentType("application/json");
                        ApiResponse apiResponse = new ApiResponse(HttpStatus.UNAUTHORIZED.value(), "Invalid JWT token!");
                        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
                        return;
                    } catch (ExpiredJwtException ex) {
                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        response.setContentType("application/json");
                        ApiResponse apiResponse = new ApiResponse(HttpStatus.UNAUTHORIZED.value(), "Expired JWT token!");
                        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
                        return;
                    } catch (UnsupportedJwtException ex) {
                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        response.setContentType("application/json");
                        ApiResponse apiResponse = new ApiResponse(HttpStatus.UNAUTHORIZED.value(), "Unsupported JWT token!");
                        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
                        return;
                    } catch (IllegalArgumentException ex) {
                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        response.setContentType("application/json");
                        ApiResponse apiResponse = new ApiResponse(HttpStatus.UNAUTHORIZED.value(), "JWT claims string is empty!");
                        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
                        return;
                    }
                }

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                    List<GrantedAuthority> authorities = (List<GrantedAuthority>) jwtService.getRoles(jwt).stream()
                            .map(role -> new SimpleGrantedAuthority(role.toString()))
                            .collect(Collectors.toList());
                    log.info("Username: {} JWT: {} Authorities: {}", username, jwt, authorities);

                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            authorities
                    );
                    SecurityContextHolder.getContext().setAuthentication(token);
                }

                filterChain.doFilter(request, response);
            }
        };
    }
}