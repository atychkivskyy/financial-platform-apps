package com.atychkivskyy.authservice.dto.response;

import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record UserResponse(
    UUID id,
    String email,
    String firstName,
    String lastName,
    Set<String> roles
) {
    public static UserResponse from(User user) {
        return new UserResponse(
            user.getId(),
            user.getEmail(),
            user.getFirstName(),
            user.getLastName(),
            user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet())
        );
    }
}
