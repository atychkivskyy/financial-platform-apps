package com.atychkivskyy.authservice.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthResponse(
    String accessToken,
    String refreshToken,
    String tokenType,
    long expiresIn,
    Instant expiresAt,
    UserResponse user
) {
    public static AuthResponse of(
        String accessToken,
        String refreshToken,
        long expiresIn,
        UserResponse user
    ) {
        return new AuthResponse(
            accessToken,
            refreshToken,
            "Bearer ",
            expiresIn,
            Instant.now().plusMillis(expiresIn),
            user
        );
    }
}
