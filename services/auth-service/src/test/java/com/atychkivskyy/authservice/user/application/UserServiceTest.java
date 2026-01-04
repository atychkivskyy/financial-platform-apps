package com.atychkivskyy.authservice.user.application;

import com.atychkivskyy.authservice.user.domain.Role;
import com.atychkivskyy.authservice.user.domain.User;
import com.atychkivskyy.authservice.user.persistence.UserRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ActiveProfiles("test")
class UserServiceTest {

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordHasher passwordHasher = mock(PasswordHasher.class);
    private final UserService userService = new UserService(userRepository, passwordHasher);

    @Test
    void shouldRegisterUserWhenEmailDoesNotExist() {
        when(userRepository.existsByEmail("user@example.com")).thenReturn(false);
        when(passwordHasher.hash("secret")).thenReturn("hashed");
        when(userRepository.save(any(User.class)))
            .thenAnswer(invocation -> invocation.getArgument(0));

        User created = userService.registerUser(
            "User@Example.com",
            "secret",
            Set.of(Role.USER)
        );

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());

        User saved = captor.getValue();
        assertThat(saved.getEmail()).isEqualTo("user@example.com");
        assertThat(saved.getPasswordHash()).isEqualTo("hashed");
        assertThat(created).isSameAs(saved);
    }

    @Test
    void shouldFailWhenEmailAlreadyExists() {
        when(userRepository.existsByEmail("user@example.com")).thenReturn(true);

        assertThatThrownBy(() ->
            userService.registerUser(
                "user@example.com",
                "secret",
                Set.of(Role.USER)
            )
        ).isInstanceOf(UserAlreadyExistsException.class);

        verifyNoInteractions(passwordHasher);
        verify(userRepository, never()).save(any());
    }

    @Test
    void shouldDisableUser() {
        UUID id = UUID.randomUUID();
        User user = User.create("user@example.com", "hash", Set.of(Role.USER));
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        userService.disableUser(id);

        assertThat(user.isEnabled()).isFalse();
    }

    @Test
    void shouldEnableUser() {
        UUID id = UUID.randomUUID();
        User user = User.create("user@example.com", "hash", Set.of(Role.USER));
        user.disable();
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        userService.enableUser(id);

        assertThat(user.isEnabled()).isTrue();
    }
}
