package com.example.auth.security.jwt;

import com.example.auth.security.entity.RefreshToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByUsername(@Param("username") String username);

    void deleteByUsername(@Param("username") String username);
}
