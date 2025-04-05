package com.example.auth.user;

import com.example.auth.user.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;
import java.util.List;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping({"", "/"})
public class UserController {

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
