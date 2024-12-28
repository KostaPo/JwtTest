package com.example.auth.entity.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthRequest {

    @Size(min = 6, max = 32, message = "Username must be between 6 and 32 characters long!")
    @Pattern(regexp = "^[a-zA-Z0-9]+$", message = "Username can only contain letters and digits!")
    private String username;

    @Size(min = 6, max = 32, message = "Password must be between 6 and 32 characters long!")
    private String password;

    @NotBlank(message = "Jabber is required: example@jabber.com")
    private String jabber;

    private Boolean rememberMe;
}
