package com.example.auth.repository;

import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
    @EntityGraph(attributePaths = "roles")
    Optional<User> findByUsername(String username);
}
