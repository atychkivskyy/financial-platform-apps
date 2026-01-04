package com.atychkivskyy.authservice.user.persistence;

import com.atychkivskyy.authservice.user.domain.Role;
import com.atychkivskyy.authservice.user.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@Testcontainers
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class UserRepositoryTest {

    @Container
    static PostgreSQLContainer<?> postgres =
        new PostgreSQLContainer<>("postgres:18.1")
            .withDatabaseName("auth_test")
            .withUsername("test")
            .withPassword("test");

    @DynamicPropertySource
    static void configureDatasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Autowired
    private UserRepository userRepository;

    @Test
    void shouldPersistAndLoadUserByEmail() {
        User user = User.create(
            "user@example.com",
            "hashed-password",
            Set.of(Role.USER)
        );

        userRepository.save(user);

        Optional<User> loaded = userRepository.findByEmail("user@example.com");

        assertThat(loaded).isPresent();
        assertThat(loaded.get().getEmail()).isEqualTo("user@example.com");
        assertThat(loaded.get().getRoles()).containsExactly(Role.USER);
    }

    @Test
    void shouldDetectExistingEmail() {
        User user = User.create(
            "existing@example.com",
            "hashed-password",
            Set.of(Role.USER)
        );

        userRepository.save(user);

        assertThat(userRepository.existsByEmail("existing@example.com")).isTrue();
        assertThat(userRepository.existsByEmail("missing@example.com")).isFalse();
    }
}
