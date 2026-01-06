package com.atychkivskyy.authservice.e2e;

import com.atychkivskyy.authservice.dto.request.RegisterRequest;
import com.atychkivskyy.authservice.dto.response.AuthResponse;
import com.atychkivskyy.authservice.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Registration E2E Tests")
class RegistrationE2ETest extends BaseE2ETest {

    @Nested
    @DisplayName("POST /api/v1/auth/register - Success Cases")
    class SuccessfulRegistration {

        @Test
        @DisplayName("Should register new user and return tokens")
        void shouldRegisterNewUserAndReturnTokens() {
            // Given
            RegisterRequest request = TestData.validRegisterRequest();

            // When
            AuthResponse response = client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                // Then
                .expectStatus().isCreated()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            // Verify response
            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isNotBlank();
            assertThat(response.refreshToken()).isNotBlank();
            assertThat(response.tokenType()).isEqualTo("Bearer ");
            assertThat(response.expiresIn()).isPositive();

            // Verify user in response
            assertThat(response.user()).isNotNull();
            assertThat(response.user().email()).isEqualTo(TestData.VALID_EMAIL);
            assertThat(response.user().firstName()).isEqualTo(TestData.VALID_FIRST_NAME);
            assertThat(response.user().lastName()).isEqualTo(TestData.VALID_LAST_NAME);
            assertThat(response.user().roles()).contains("ROLE_USER");

            // Verify database state
            Optional<User> savedUser = userRepository.findByEmail(TestData.VALID_EMAIL);
            assertThat(savedUser).isPresent();
            assertThat(savedUser.get().isEnabled()).isTrue();
            assertThat(savedUser.get().isAccountNonLocked()).isTrue();
            assertThat(savedUser.get().getFailedLoginAttempts()).isZero();
        }

        @Test
        @DisplayName("Should normalize email to lowercase")
        void shouldNormalizeEmailToLowercase() {
            // Given
            RegisterRequest request = TestData.registerRequest("TEST.USER@EXAMPLE.COM");

            // When
            AuthResponse response = client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                // Then
                .expectStatus().isCreated()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.user().email()).isEqualTo("test.user@example.com");

            // Verify in database
            assertThat(userRepository.findByEmail("test.user@example.com")).isPresent();
            assertThat(userRepository.findByEmail("TEST.USER@EXAMPLE.COM")).isEmpty();
        }

        @Test
        @DisplayName("Should trim whitespace from names")
        void shouldTrimWhitespaceFromNames() {
            // Given
            RegisterRequest request = new RegisterRequest(
                "trim.test@example.com",
                TestData.VALID_PASSWORD,
                "  John  ",
                "  Doe  "
            );

            // When
            AuthResponse response = client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                // Then
                .expectStatus().isCreated()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.user().firstName()).isEqualTo("John");
            assertThat(response.user().lastName()).isEqualTo("Doe");
        }

        @Test
        @DisplayName("Should assign default ROLE_USER to new user")
        void shouldAssignDefaultRole() {
            // When
            AuthResponse response = client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validRegisterRequest())
                .exchange()
                // Then
                .expectStatus().isCreated()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.user().roles())
                .hasSize(1)
                .contains("ROLE_USER");
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/register - Validation Errors")
    class ValidationErrors {

        @Test
        @DisplayName("Should return 400 for invalid email format")
        void shouldRejectInvalidEmailFormat() {
            RegisterRequest request = TestData.registerRequest(TestData.Invalid.INVALID_EMAIL);

            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.title").isEqualTo("Validation Error");
        }

        @Test
        @DisplayName("Should return 400 for blank email")
        void shouldRejectBlankEmail() {
            RegisterRequest request = TestData.registerRequest(TestData.Invalid.BLANK);

            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should return 400 for weak password")
        void shouldRejectWeakPassword() {
            RegisterRequest request = TestData.registerRequest(TestData.VALID_EMAIL, TestData.Invalid.INVALID_PASSWORD);

            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should return 400 for password without uppercase")
        void shouldRejectPasswordWithoutUppercase() {
            RegisterRequest request = TestData.registerRequest(TestData.VALID_EMAIL, "securepass123!");

            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should return 400 for password without special character")
        void shouldRejectPasswordWithoutSpecialChar() {
            RegisterRequest request = TestData.registerRequest(TestData.VALID_EMAIL, "SecurePass123");

            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should return 400 for blank first name")
        void shouldRejectBlankFirstName() {
            RegisterRequest request = TestData.registerRequestWithName(TestData.Invalid.BLANK, TestData.VALID_LAST_NAME);

            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should return 400 for blank last name")
        void shouldRejectBlankLastName() {
            RegisterRequest request = TestData.registerRequestWithName(TestData.VALID_FIRST_NAME, TestData.Invalid.BLANK);

            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isBadRequest();
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/register - Conflict Errors")
    class ConflictErrors {

        @Test
        @DisplayName("Should return 409 when email already exists")
        void shouldRejectDuplicateEmail() {
            // Given - First registration
            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validRegisterRequest())
                .exchange()
                .expectStatus().isCreated();

            // When - Second registration with same email
            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validRegisterRequest())
                .exchange()
                // Then
                .expectStatus().isEqualTo(409)
                .expectBody()
                .jsonPath("$.title").isEqualTo("User Already Exists");
        }

        @Test
        @DisplayName("Should return 409 for same email with different case")
        void shouldRejectDuplicateEmailDifferentCase() {
            // Given
            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.registerRequest("user@example.com"))
                .exchange()
                .expectStatus().isCreated();

            // When
            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.registerRequest("USER@EXAMPLE.COM"))
                .exchange()
                // Then
                .expectStatus().isEqualTo(409);
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/register - Token Validation")
    class TokenValidation {

        @Test
        @DisplayName("Should return valid access token that can access protected endpoints")
        void shouldReturnValidAccessToken() {
            // Given - Register and get tokens
            AuthResponse authResponse = client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validRegisterRequest())
                .exchange()
                .expectStatus().isCreated()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            // When - Use access token to access protected endpoint
            assertThat(authResponse).isNotNull();
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                // Then
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo(TestData.VALID_EMAIL);
        }

        @Test
        @DisplayName("Should return valid refresh token that can be used to get new access token")
        void shouldReturnValidRefreshToken() {
            // Given - Register and get tokens
            AuthResponse authResponse = client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validRegisterRequest())
                .exchange()
                .expectStatus().isCreated()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            // When - Use refresh token
            assertThat(authResponse).isNotNull();
            AuthResponse refreshResponse = client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                // Then
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(refreshResponse).isNotNull();
            assertThat(refreshResponse.accessToken()).isNotBlank();
            assertThat(refreshResponse.accessToken()).isNotEqualTo(authResponse.accessToken());
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/register - Database State")
    class DatabaseState {

        @Test
        @DisplayName("Should persist refresh token in database")
        void shouldPersistRefreshToken() {
            // When
            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validRegisterRequest())
                .exchange()
                .expectStatus().isCreated();

            // Then
            User user = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            long tokenCount = refreshTokenRepository.countActiveTokensByUserId(
                user.getId(),
                java.time.Instant.now()
            );
            assertThat(tokenCount).isEqualTo(1);
        }

        @Test
        @DisplayName("Should hash password before storing")
        void shouldHashPassword() {
            // When
            client.post()
                .uri(authUrl("/register"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validRegisterRequest())
                .exchange()
                .expectStatus().isCreated();

            // Then
            User user = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            assertThat(user.getPasswordHash())
                .isNotBlank()
                .isNotEqualTo(TestData.VALID_PASSWORD)
                .startsWith("$argon2"); // Argon2 hash prefix
        }
    }
}
