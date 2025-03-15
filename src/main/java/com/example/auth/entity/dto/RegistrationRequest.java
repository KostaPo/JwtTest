package com.example.auth.entity.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RegistrationRequest {

    @NotBlank(message = "Username cannot be empty!")
    @Size(min = 6, max = 32, message = "Username must be between 6 and 32 characters long!")
    @Pattern(regexp = "^[a-zA-Z0-9]+$", message = "Only letters and digits!")
    private String username;

    @NotBlank(message = "Password cannot be empty!")
    @Size(min = 6, max = 32, message = "Password must be between 6 and 32 characters long!")
    private String password;
}
