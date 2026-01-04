package com.atychkivskyy.authservice.user.application;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ActiveProfiles("test")
class BCryptPasswordHasherTest {

    private final BCryptPasswordHasher hasher = new BCryptPasswordHasher(new BCryptPasswordEncoder(12));

    @Test
    void shouldHashPassword() {
        String raw = "secret";

        String hashed = hasher.hash(raw);

        assertThat(new BCryptPasswordEncoder().matches(raw, hashed)).isTrue();
    }

    @Test
    void shouldProduceDifferentHashesFromSameInput() {
        String raw = "secret";

        String h1 = hasher.hash(raw);
        String h2 = hasher.hash(raw);

        assertThat(h1).isNotEqualTo(h2);
    }

    @Test
    void shouldFailOnNullPassword() {
        assertThatThrownBy(() -> hasher.hash(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("rawPassword");
    }
}
