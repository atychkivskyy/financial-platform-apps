package com.atychkivskyy.authservice.user.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

public record RegisterUserRequest(

    @Email
    @NotBlank
    String email,

    @NotBlank
    String password,

    @NotEmpty
    Set<String> roles

) {
}
