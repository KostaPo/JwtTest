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

    private final JedisBasedProxyManager proxyManager;

    @Value("${rate-limit.capacity}")
    private int capacity;

    @Value("${rate-limit.duration}")
    private int durationMinutes;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {


        ObjectMapper objectMapper = new ObjectMapper();

        String key = String.format("%s:%s:%s", request.getRemoteAddr(), request.getMethod(), request.getRequestURI());
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);

        // 1. Создаем конфигурацию лимита
        Bandwidth limit = Bandwidth.builder()
                .capacity(capacity)
                .refillIntervally(capacity, Duration.ofMinutes(durationMinutes))
                .build();

        // 2. Собираем конфигурацию bucket
        BucketConfiguration bucketConfig = BucketConfiguration.builder()
                .addLimit(limit)
                .build();

        // 3. Получаем bucket
        Bucket bucket = proxyManager.builder().build(keyBytes, bucketConfig);

        // 4. Проверяем лимит
        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            ApiResponse apiResponse = new ApiResponse("RATE LIMIT EXCEED!");
            response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
        }
    }
}