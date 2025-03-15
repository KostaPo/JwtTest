package com.example.auth.service;

import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.entity.UserRole;
import com.example.auth.entity.dto.AuthRequest;
import com.example.auth.entity.dto.RegistrationRequest;
import com.example.auth.exception.UserNotFoundException;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class AppUserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(() -> new UserNotFoundException(
                String.format("User '%s' not found", username)
        ));
    }

    public List<User> findAll() {
        return userRepository.findAllWithRoles();
    }

    public void save(RegistrationRequest registrationRequest) {
        User user = new User();
        user.setUsername(registrationRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        user.setRoles(List.of(Role.builder().name(UserRole.ROLE_USER.name()).build()));
        userRepository.save(user);
    }
}
