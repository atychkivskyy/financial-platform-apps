package com.atychkivskyy.authservice.user.domain;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.*;

class UserTest {

    @Test
    void shouldCreateUserWithNormalizedEmailAndEnabledByDefault() {
        String email = "User@Example.COM";
        String passwordHash = "hashed-password";
        Set<Role> roles = Set.of(Role.USER);

        User user = User.create(email, passwordHash, roles);

        assertThat(user.getId()).isNotNull();
        assertThat(user.getEmail()).isEqualTo("user@example.com");
        assertThat(user.getPasswordHash()).isEqualTo(passwordHash);
        assertThat(user.getRoles()).containsExactly(Role.USER);
        assertThat(user.isEnabled()).isTrue();
        assertThat(user.getCreatedAt()).isNotNull();
    }

    @Test
    void shouldDisableAndEnableUser() {
        User user = User.create(
            "user@example.com",
            "hashedPassword",
            Set.of(Role.USER)
        );

        user.disable();

        assertThat(user.isEnabled()).isFalse();

        user.enable();

        assertThat(user.isEnabled()).isTrue();
    }

    @Test
    void shouldFailWhenCreatingUserWithNullEmail() {
        assertThatThrownBy(() ->
            User.create(null, "hashed-password", Set.of(Role.USER))
        )
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("email");
    }

    @Test
    void shouldFailWhenCreatingUserWithNullPasswordHash() {
        assertThatThrownBy(() ->
            User.create("user@example.com", null, Set.of(Role.USER))
        )
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("passwordHash");
    }

    @Test
    void shouldFailWhenCreatingUserWithNullRoles() {
        assertThatThrownBy(() ->
            User.create("user@example.com", "hashed-password", null)
        )
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("roles");
    }

    @Test
    void shouldFailWhenCreatingUserWithNoRoles() {
        String email = "user@example.com";
        String passwordHash = "hashed-password";

        assertThatThrownBy(() ->
            User.create(email, passwordHash, Set.of())
        )
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("at least one role");
    }
}
