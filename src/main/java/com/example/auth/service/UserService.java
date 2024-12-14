package com.example.auth.service;

import com.example.auth.dto.UserRequestDto;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleService roleService;


    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public void addUser(UserRequestDto userDto) {
        User user = new User();
        user.setUsername(userDto.getUsername());
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        user.setRoles(List.of(roleService.getRoleByName("ROLE_USER")));
        userRepository.save(user);
    }
}
