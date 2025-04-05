package com.example.auth.security.jwt;

import com.example.auth.security.entity.RefreshToken;
import com.example.auth.exception.TokenNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final JwtService jwtService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final RefreshTokenRepository tokenRepository;

    public String getTokenByUsername(String username) {
        RefreshToken rToken = tokenRepository.findByUsername(username)
                .orElseThrow(() -> new TokenNotFoundException(String.format("Can't find token by username '%s'!", username)));
        return rToken.getToken();
    }

    public void saveToken(String rToken) {
        Optional<RefreshToken> oldToken = tokenRepository.findByUsername(jwtService.getUsername(rToken));
        if(oldToken.isPresent()) {
            oldToken.get().setExpired(jwtService.getExpirationDate(rToken));
            oldToken.get().setToken(passwordEncoder.encode(rToken));
            tokenRepository.save(oldToken.get());
        } else {
            RefreshToken newToken = new RefreshToken();
            newToken.setUsername(jwtService.getUsername(rToken));
            newToken.setExpired(jwtService.getExpirationDate(rToken));
            newToken.setToken(passwordEncoder.encode(rToken));
            tokenRepository.save(newToken);
        }
    }

    public boolean isTokenEquals(String sourceToken, String encryptedToken) {
        return passwordEncoder.matches(sourceToken, encryptedToken);
    }

    @Transactional
    public void removeRefreshTokenByUsername(String username) {
        tokenRepository.deleteByUsername(username);
    }

}
