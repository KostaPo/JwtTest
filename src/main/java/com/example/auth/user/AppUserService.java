package com.example.auth.user;

import com.example.auth.user.entity.Role;
import com.example.auth.user.entity.User;
import com.example.auth.user.entity.UserRole;
import com.example.auth.user.entity.dto.RegistrationRequest;
import com.example.auth.exception.UserNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
