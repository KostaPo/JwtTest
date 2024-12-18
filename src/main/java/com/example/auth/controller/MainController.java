package com.example.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;

@Controller
@RequestMapping({"", "/"})
public class MainController {

    @GetMapping("/secured")
    public ResponseEntity<String> secured() {
        return ResponseEntity.ok("secured");
    }

    @GetMapping("/unsecured")
    public ResponseEntity<String> unsecured() {
        return ResponseEntity.ok("unsecured");
    }

    @GetMapping("/info")
    public ResponseEntity<String> info(Principal principal) {
        return ResponseEntity.ok(principal.toString());
    }

    @GetMapping("/admin")
    //@PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> adminData() {
        return ResponseEntity.ok("admin hello! ");
    }
}
