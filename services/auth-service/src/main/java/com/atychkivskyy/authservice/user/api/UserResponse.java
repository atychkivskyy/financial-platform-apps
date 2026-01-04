package com.atychkivskyy.authservice.user.api;

import com.atychkivskyy.authservice.user.domain.User;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record UserResponse(
    UUID id,
    String email,
    boolean enabled,
    Set<String> roles,
    Instant createdAt
) {
    static UserResponse from(User user) {
        return new UserResponse(
            user.getId(),
            user.getEmail(),
            user.isEnabled(),
            user.getRoles()
                .stream()
                .map(Enum::name)
                .collect(Collectors.toSet()),
            user.getCreatedAt()
        );
    }
}
