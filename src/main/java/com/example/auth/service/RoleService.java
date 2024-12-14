package com.example.auth.service;

import com.example.auth.entity.Role;
import com.example.auth.exception.RoleNotFoundException;
import com.example.auth.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;

    public Role getRoleByName(String name) {
        return roleRepository.findByName(name)
                .orElseThrow(() -> new RoleNotFoundException("Role with name '" + name + "' not found"));
    }
}
