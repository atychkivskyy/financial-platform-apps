package com.atychkivskyy.authservice.integration;

import com.atychkivskyy.authservice.entity.RefreshToken;
import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Entity JPA Mapping Integration Tests")
class EntityMappingIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private TestEntityManager entityManager;

    @Test
    @DisplayName("should persist and retrieve Role entity")
    void shouldPersistAndRetrieveRole() {
        Role role = new Role("ROLE_USER", "Standard user role");

        Role savedRole = entityManager.persistFlushFind(role);

        assertThat(savedRole.getId()).isNotNull();
        assertThat(savedRole.getName()).isEqualTo("ROLE_USER");
        assertThat(savedRole.getDescription()).isEqualTo("Standard user role");
        assertThat(savedRole.getCreatedAt()).isNotNull();
    }

    @Test
    @DisplayName("should persist and retrieve User entity with roles")
    void shouldPersistAndRetrieveUserWithRoles() {
        Role role = entityManager.persistFlushFind(new Role("ROLE_USER"));

        User user = User.builder()
            .email("test@example.com")
            .passwordHash("hashedPassword")
            .firstName("John")
            .lastName("Doe")
            .roles(Set.of(role))
            .build();

        User savedUser = entityManager.persistFlushFind(user);

        assertThat(savedUser.getId()).isNotNull();
        assertThat(savedUser.getEmail()).isEqualTo("test@example.com");
        assertThat(savedUser.getCreatedAt()).isNotNull();
        assertThat(savedUser.getUpdatedAt()).isNotNull();
        assertThat(savedUser.getRoles()).hasSize(1);
        assertThat(savedUser.hasRole("ROLE_USER")).isTrue();
    }

    @Test
    @DisplayName("should persist and retrieve RefreshToken entity")
    void shouldPersistAndRetrieveRefreshToken() {
        Role role = entityManager.persistFlushFind(new Role("ROLE_USER"));
        User user = User.builder()
            .email("test@example.com")
            .passwordHash("hashedPassword")
            .firstName("John")
            .lastName("Doe")
            .roles(Set.of(role))
            .build();
        User savedUser = entityManager.persistFlushFind(user);

        RefreshToken refreshToken = RefreshToken.create(
            savedUser,
            "secure-random-token",
            Instant.now().plus(7, ChronoUnit.DAYS)
        );

        RefreshToken savedToken = entityManager.persistFlushFind(refreshToken);

        assertThat(savedToken.getId()).isNotNull();
        assertThat(savedToken.getToken()).isEqualTo("secure-random-token");
        assertThat(savedToken.getUser().getId()).isEqualTo(savedUser.getId());
        assertThat(savedToken.getCreatedAt()).isNotNull();
        assertThat(savedToken.isRevoked()).isFalse();
    }

    @Test
    @DisplayName("should update User version on modification")
    void shouldUpdateUserVersionOnModification() {
        Role role = entityManager.persistFlushFind(new Role("ROLE_USER"));
        User user = User.builder()
            .email("test@example.com")
            .passwordHash("hashedPassword")
            .firstName("John")
            .lastName("Doe")
            .roles(Set.of(role))
            .build();

        User savedUser = entityManager.persistAndFlush(user);
        Long initialVersion = savedUser.getVersion();

        savedUser.updateProfile("Jane", "Smith");
        entityManager.persistAndFlush(savedUser);
        entityManager.clear();

        User updatedUser = entityManager.find(User.class, savedUser.getId());

        assertThat(updatedUser).isNotNull();
        assertThat(updatedUser.getVersion()).isGreaterThan(initialVersion);
        assertThat(updatedUser.getFirstName()).isEqualTo("Jane");
    }
}
