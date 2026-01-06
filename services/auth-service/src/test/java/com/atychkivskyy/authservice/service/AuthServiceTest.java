package com.atychkivskyy.authservice.service;

import com.atychkivskyy.authservice.dto.request.LoginRequest;
import com.atychkivskyy.authservice.dto.request.RegisterRequest;
import com.atychkivskyy.authservice.dto.response.AuthResponse;
import com.atychkivskyy.authservice.dto.response.UserResponse;
import com.atychkivskyy.authservice.entity.RefreshToken;
import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;
import com.atychkivskyy.authservice.event.AuthEventPublisher;
import com.atychkivskyy.authservice.exception.InvalidCredentialsException;
import com.atychkivskyy.authservice.exception.UserAlreadyExistsException;
import com.atychkivskyy.authservice.repository.RoleRepository;
import com.atychkivskyy.authservice.repository.UserRepository;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthService Unit Tests")
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private AuthEventPublisher eventPublisher;

    @InjectMocks
    private AuthService authService;

    @Captor
    private ArgumentCaptor<User> userCaptor;

    private Role defaultRole;
    private User testUser;
    private Role userRole;
    private UUID userId;


    @BeforeEach
    void setUp() {
        defaultRole = new Role("ROLE_USER");
        userId = UUID.randomUUID();
        userRole = new Role("ROLE_USER", "Standard user");

        testUser = User.builder()
            .email("test@example.com")
            .passwordHash("hashedPassword")
            .firstName("John")
            .lastName("Doe")
            .roles(Set.of(defaultRole))
            .enabled(true)
            .build();
    }

    @Nested
    @DisplayName("Registration Tests")
    class RegistrationTests {

        @Test
        @DisplayName("Should register user successfully with valid data")
        void shouldRegisterUserSuccessfully() {
            // Given
            RegisterRequest request = new RegisterRequest(
                "newuser@example.com",
                "SecurePass123!",
                "Jane",
                "Smith"
            );

            when(userRepository.existsByEmail(anyString())).thenReturn(false);
            when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(defaultRole));
            when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User user = invocation.getArgument(0);
                return user;
            });
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(900000L);

            RefreshToken refreshToken = mock(RefreshToken.class);
            when(refreshToken.getToken()).thenReturn("refresh-token");
            when(refreshTokenService.createRefreshToken(any())).thenReturn(refreshToken);

            // When
            AuthResponse response = authService.register(request);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isEqualTo("access-token");
            assertThat(response.refreshToken()).isEqualTo("refresh-token");
            assertThat(response.tokenType()).isEqualTo("Bearer");

            verify(userRepository).save(userCaptor.capture());
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getEmail()).isEqualTo("newuser@example.com");
            assertThat(savedUser.getFirstName()).isEqualTo("Jane");
            assertThat(savedUser.getLastName()).isEqualTo("Smith");

            verify(eventPublisher).publishUserRegistered(any(User.class));
        }

        @Test
        @DisplayName("Should throw exception when email already exists")
        void shouldThrowExceptionWhenEmailExists() {
            // Given
            RegisterRequest request = new RegisterRequest(
                "existing@example.com",
                "SecurePass123!",
                "Jane",
                "Smith"
            );

            when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

            // When/Then
            assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining("existing@example.com");

            verify(userRepository, never()).save(any());
            verify(eventPublisher, never()).publishUserRegistered(any());
        }
    }

    @Nested
    @DisplayName("Login Tests")
    class LoginTests {

        private static final String TEST_IP = "127.0.0.1";
        private static final String TEST_USER_AGENT = "Mozilla/5.0";

        @Test
        @DisplayName("Should login successfully with valid credentials")
        void shouldLoginSuccessfully() {
            // Given
            LoginRequest request = new LoginRequest("test@example.com", "correctPassword");

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("correctPassword", "hashedPassword")).thenReturn(true);
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(jwtService.getAccessTokenExpiration()).thenReturn(900000L);

            RefreshToken refreshToken = mock(RefreshToken.class);
            when(refreshToken.getToken()).thenReturn("refresh-token");
            when(refreshTokenService.createRefreshToken(any())).thenReturn(refreshToken);

            // When
            AuthResponse response = authService.login(request, TEST_IP, TEST_USER_AGENT);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isEqualTo("access-token");
            assertThat(response.refreshToken()).isEqualTo("refresh-token");

            verify(eventPublisher).publishUserLoginSuccess(eq(testUser), eq(TEST_IP), eq(TEST_USER_AGENT));
        }

        @Test
        @DisplayName("Should throw exception for invalid password")
        void shouldThrowExceptionForInvalidPassword() {
            // Given
            LoginRequest request = new LoginRequest("test@example.com", "wrongPassword");

            when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches("wrongPassword", "hashedPassword")).thenReturn(false);

            // When/Then
            assertThatThrownBy(() -> authService.login(request, TEST_IP, TEST_USER_AGENT))
                .isInstanceOf(InvalidCredentialsException.class);

            verify(eventPublisher).publishUserLoginFailure(eq("test@example.com"), eq(TEST_IP), eq(TEST_USER_AGENT), anyString());
        }

        @Test
        @DisplayName("Should throw exception for non-existent user")
        void shouldThrowExceptionForNonExistentUser() {
            // Given
            LoginRequest request = new LoginRequest("notfound@example.com", "password");

            when(userRepository.findByEmail("notfound@example.com")).thenReturn(Optional.empty());

            // When/Then
            assertThatThrownBy(() -> authService.login(request, TEST_IP, TEST_USER_AGENT))
                .isInstanceOf(InvalidCredentialsException.class);

            verify(eventPublisher).publishUserLoginFailure(eq("notfound@example.com"), eq(TEST_IP), eq(TEST_USER_AGENT), anyString());
        }
    }

    @Nested
    @DisplayName("getCurrentUser")
    class GetCurrentUser {

        @Test
        @DisplayName("should return user response when user exists")
        void shouldReturnUserResponseWhenUserExists() {
            when(userRepository.findByIdWithRoles(userId)).thenReturn(Optional.of(testUser));

            UserResponse response = authService.getCurrentUser(userId);

            assertThat(response).isNotNull();
            assertThat(response.email()).isEqualTo("test@example.com");
            assertThat(response.firstName()).isEqualTo("John");
            assertThat(response.lastName()).isEqualTo("Doe");
            assertThat(response.roles()).contains("ROLE_USER");

            verify(userRepository).findByIdWithRoles(userId);
        }

        @Test
        @DisplayName("should throw exception when user not found")
        void shouldThrowExceptionWhenUserNotFound() {
            when(userRepository.findByIdWithRoles(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.getCurrentUser(userId))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining(userId.toString());

            verify(userRepository).findByIdWithRoles(userId);
        }

        @Test
        @DisplayName("should include all user roles")
        void shouldIncludeAllUserRoles() {
            Role adminRole = new Role("ROLE_ADMIN", "Administrator");
            Role moderatorRole = new Role("ROLE_MODERATOR", "Moderator");

            User multiRoleUser = User.builder()
                .email("admin@example.com")
                .passwordHash("hash")
                .firstName("Admin")
                .lastName("User")
                .enabled(true)
                .roles(Set.of(userRole, adminRole, moderatorRole))
                .build();

            when(userRepository.findByIdWithRoles(userId)).thenReturn(Optional.of(multiRoleUser));

            UserResponse response = authService.getCurrentUser(userId);

            assertThat(response.roles())
                .hasSize(3)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MODERATOR");
        }
    }

    @Nested
    @DisplayName("logoutAllDevices")
    class LogoutAllDevices {

        @Test
        @DisplayName("should revoke all tokens for user")
        void shouldRevokeAllTokensForUser() {
            when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));

            authService.logoutAllDevices(userId);

            verify(userRepository).findById(userId);
            verify(refreshTokenService).revokeAllUserTokens(testUser);
        }

        @Test
        @DisplayName("should throw exception when user not found")
        void shouldThrowExceptionWhenUserNotFound() {
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.logoutAllDevices(userId))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining(userId.toString());

            verify(userRepository).findById(userId);
            verifyNoInteractions(refreshTokenService);
        }
    }

    @Nested
    @DisplayName("logout")
    class Logout {

        @Test
        @DisplayName("should revoke refresh token")
        void shouldRevokeRefreshToken() {
            String refreshToken = "valid-refresh-token";

            authService.logout(refreshToken);

            verify(refreshTokenService).revokeRefreshToken(refreshToken);
        }
    }
}
