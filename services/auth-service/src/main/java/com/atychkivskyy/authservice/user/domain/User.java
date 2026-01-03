package com.atychkivskyy.authservice.user.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(
    name = "users",
    uniqueConstraints = {
        @UniqueConstraint(name = "uk_users_email", columnNames = "email")
    }
)
public class User {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Email
    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id")
    )
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Set<Role> roles;

    @Column(nullable = false)
    private boolean enabled;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    protected User() {
    }

    private User(
        UUID id,
        String email,
        String passwordHash,
        Set<Role> roles,
        boolean enabled,
        Instant createdAt
    ) {
        this.id = id;
        this.email = email;
        this.passwordHash = passwordHash;
        this.roles = roles;
        this.enabled = enabled;
        this.createdAt = createdAt;
    }

    public static User create(
        String email,
        String passwordHash,
        Set<Role> roles
    ) {
        Objects.requireNonNull(email, "email must not be null");
        Objects.requireNonNull(passwordHash, "passwordHash must not be null");
        Objects.requireNonNull(roles, "roles must not be null");

        if (roles.isEmpty()) {
            throw new IllegalArgumentException("user must have at least one role");
        }

        return new User(
            UUID.randomUUID(),
            email.toLowerCase(),
            passwordHash,
            roles,
            true,
            Instant.now()
        );
    }

    public void disable() {
        this.enabled = false;
    }

    public void enable() {
        this.enabled = true;
    }

    public UUID getId() {
        return id;
    }

    public @Email String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
