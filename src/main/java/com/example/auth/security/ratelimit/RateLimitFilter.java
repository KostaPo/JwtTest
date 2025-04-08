package com.example.auth.security.ratelimit;

import com.example.auth.exception.ApiResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.redis.jedis.cas.JedisBasedProxyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final JedisBasedProxyManager<byte[]> jedisBasedProxyManager;

    @Value("${rate-limit.capacity.main}")
    private int mainCapacity;

    @Value("${rate-limit.capacity.options}")
    private int optionsCapacity;

    @Value("${rate-limit.duration}")
    private int durationMinutes;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {


        ObjectMapper objectMapper = new ObjectMapper();

        String method = request.getMethod().toUpperCase();
        String path = request.getRequestURI();
        String clientIp = request.getRemoteAddr();

        String key = String.format("%s:%s:%s", clientIp, method, path);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        int capacity = "OPTIONS".equals(method) ? optionsCapacity : mainCapacity;

        Bandwidth limit = Bandwidth.builder()
                .capacity(capacity)
                .refillIntervally(capacity, Duration.ofMinutes(durationMinutes))
                .build();

        BucketConfiguration bucketConfig = BucketConfiguration.builder()
                .addLimit(limit)
                .build();

        Bucket bucket = jedisBasedProxyManager.builder().build(keyBytes, bucketConfig);

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            addCorsHeaders(response);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            ApiResponse apiResponse = new ApiResponse("RATE LIMIT EXCEED!");
            response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
        }
    }

    private void addCorsHeaders(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "http://localhost:5173");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
        response.setHeader("Access-Control-Max-Age", "600");
        response.setHeader("Access-Control-Allow-Credentials", "true");
    }
}