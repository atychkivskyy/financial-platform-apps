package com.atychkivskyy.authservice.event;

import java.time.Instant;
import java.util.UUID;

public record UserLoginEvent(
    UUID eventId,
    UUID userId,
    String email,
    String ipAddress,
    String userAgent,
    boolean successful,
    String failureReason,
    Instant occurredAt
) {
    public static UserLoginEvent success(UUID userId, String email, String ipAddress, String userAgent) {
        return new UserLoginEvent(
            UUID.randomUUID(),
            userId,
            email,
            ipAddress,
            userAgent,
            true,
            null,
            Instant.now()
        );
    }

    public static UserLoginEvent failure(String email, String ipAddress, String userAgent, String reason) {
        return new UserLoginEvent(
            UUID.randomUUID(),
            null,
            email,
            ipAddress,
            userAgent,
            false,
            reason,
            Instant.now()
        );
    }

}
