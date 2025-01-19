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
import java.util.List;

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
    public ResponseEntity<?> adminData(Principal principal) {
        log.info("user [{}] get ADMIN info", principal.getName());
        List<User> userList = userService.findAll();
        return ResponseEntity.ok(userList);
    }
}
