package com.example.auth.controller;

import com.example.auth.entity.User;
import com.example.auth.service.AppUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping({"", "/"})
public class MainController {

    private final AppUserService userService;

    @GetMapping("/info")
    public ResponseEntity<User> info(Principal principal) {
        log.info("user [{}] get info", principal.getName());
        User user = userService.findByUsername(principal.getName());
        return ResponseEntity.ok(user);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> adminData() {
        return ResponseEntity.ok("admin hello! ");
    }
}
