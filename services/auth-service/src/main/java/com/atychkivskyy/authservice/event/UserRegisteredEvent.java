package com.atychkivskyy.authservice.event;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record UserRegisteredEvent(
    UUID eventId,
    UUID userId,
    String email,
    String firstName,
    String lastName,
    Set<String> roles,
    Instant occurredAt
) {
    public static UserRegisteredEvent create(
        UUID userId,
        String email,
        String firstName,
        String lastName,
        Set<String> roles
    ) {
        return new UserRegisteredEvent(
            UUID.randomUUID(),
            userId,
            email,
            firstName,
            lastName,
            roles,
            Instant.now()
        );
    }
}
