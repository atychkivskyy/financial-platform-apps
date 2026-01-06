package com.atychkivskyy.authservice.e2e;


import com.atychkivskyy.authservice.dto.response.AuthResponse;
import com.atychkivskyy.authservice.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;


@DisplayName("Login E2E Tests")
class LoginE2ETest extends BaseE2ETest {
    @BeforeEach
    void registerTestUser() {
        client.post()
            .uri(authUrl("/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validRegisterRequest())
            .exchange()
            .expectStatus().isCreated();
    }

    @Nested
    @DisplayName("POST /api/v1/auth/login - Success Cases")
    class SuccessfulLogin {

        @Test
        @DisplayName("Should login with valid credentials")
        void shouldLoginWithValidCredentials() {
            AuthResponse response = client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validLoginRequest())
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isNotBlank();
            assertThat(response.refreshToken()).isNotBlank();
            assertThat(response.tokenType()).isEqualTo("Bearer");
            assertThat(response.expiresIn()).isPositive();
            assertThat(response.user()).isNotNull();
            assertThat(response.user().email()).isEqualTo(TestData.VALID_EMAIL);
            assertThat(response.user().roles()).contains("ROLE_USER");
        }

        @Test
        @DisplayName("Should login with email in different case")
        void shouldLoginWithDifferentCaseEmail() {
            AuthResponse response = client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest("JOHN.DOE@EXAMPLE.COM", TestData.VALID_PASSWORD))
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.user().email()).isEqualTo(TestData.VALID_EMAIL);
        }

        @Test
        @DisplayName("Should return different tokens on each login")
        void shouldReturnDifferentTokensOnEachLogin() {
            AuthResponse firstLogin = client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validLoginRequest())
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            AuthResponse secondLogin = client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validLoginRequest())
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(firstLogin).isNotNull();
            assertThat(secondLogin).isNotNull();
            assertThat(firstLogin.accessToken()).isNotEqualTo(secondLogin.accessToken());
            assertThat(firstLogin.refreshToken()).isNotEqualTo(secondLogin.refreshToken());
        }

        @Test
        @DisplayName("Should reset failed attempts on successful login")
        void shouldResetFailedAttemptsOnSuccessfulLogin() {
            // Create some failed attempts
            for (int i = 0; i < 3; i++) {
                client.post()
                    .uri(authUrl("/login"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                    .exchange()
                    .expectStatus().isUnauthorized();
            }

            // Verify failed attempts recorded
            User userBefore = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            assertThat(userBefore.getFailedLoginAttempts()).isEqualTo(3);

            // Successful login
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validLoginRequest())
                .exchange()
                .expectStatus().isOk();

            // Failed attempts should be reset
            User userAfter = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            assertThat(userAfter.getFailedLoginAttempts()).isZero();
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/login - Authentication Failures")
    class AuthenticationFailures {

        @Test
        @DisplayName("Should return 401 for wrong password")
        void shouldRejectWrongPassword() {
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.title").isEqualTo("Authentication Failed");
        }

        @Test
        @DisplayName("Should return 401 for non-existent user")
        void shouldRejectNonExistentUser() {
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest("nonexistent@example.com", TestData.VALID_PASSWORD))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.title").isEqualTo("Authentication Failed");
        }

        @Test
        @DisplayName("Should increment failed login attempts")
        void shouldIncrementFailedLoginAttempts() {
            // First failed attempt
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                .exchange()
                .expectStatus().isUnauthorized();

            User userAfterFirst = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            assertThat(userAfterFirst.getFailedLoginAttempts()).isEqualTo(1);

            // Second failed attempt
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                .exchange()
                .expectStatus().isUnauthorized();

            User userAfterSecond = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            assertThat(userAfterSecond.getFailedLoginAttempts()).isEqualTo(2);
        }

        @Test
        @DisplayName("Should not reveal if user exists")
        void shouldNotRevealUserExistence() {
            // Wrong password for existing user
            String existingUserResponse = client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

            // Non-existent user
            String nonExistentResponse = client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest("nonexistent@example.com", TestData.VALID_PASSWORD))
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

            // Both should have same error message (not revealing user existence)
            assertThat(existingUserResponse).contains("Authentication Failed");
            assertThat(nonExistentResponse).contains("Authentication Failed");
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/login - Account Locking")
    class AccountLocking {

        @Test
        @DisplayName("Should lock account after 5 failed attempts")
        void shouldLockAccountAfterMaxFailedAttempts() {
            // 5 failed attempts
            for (int i = 0; i < 5; i++) {
                client.post()
                    .uri(authUrl("/login"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                    .exchange()
                    .expectStatus().isUnauthorized();
            }

            // Verify account is locked
            User lockedUser = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            assertThat(lockedUser.isAccountNonLocked()).isFalse();
            assertThat(lockedUser.getLockTime()).isNotNull();
            assertThat(lockedUser.getFailedLoginAttempts()).isEqualTo(5);
        }

        @Test
        @DisplayName("Should return 423 for locked account with correct password")
        void shouldRejectLockedAccountWithCorrectPassword() {
            // Lock the account
            for (int i = 0; i < 5; i++) {
                client.post()
                    .uri(authUrl("/login"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                    .exchange();
            }

            // Try with correct password
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validLoginRequest())
                .exchange()
                .expectStatus().isEqualTo(423)
                .expectBody()
                .jsonPath("$.title").isEqualTo("Account Locked");
        }

        @Test
        @DisplayName("Should return 423 for locked account with wrong password")
        void shouldRejectLockedAccountWithWrongPassword() {
            // Lock the account
            for (int i = 0; i < 5; i++) {
                client.post()
                    .uri(authUrl("/login"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                    .exchange();
            }

            // Try with wrong password - should still show locked, not invalid credentials
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "AnotherWrong1!"))
                .exchange()
                .expectStatus().isEqualTo(423);
        }

        @Test
        @DisplayName("Should not increment failed attempts for locked account")
        void shouldNotIncrementFailedAttemptsWhenLocked() {
            // Lock the account
            for (int i = 0; i < 5; i++) {
                client.post()
                    .uri(authUrl("/login"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                    .exchange();
            }

            User lockedUser = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            int attemptsWhenLocked = lockedUser.getFailedLoginAttempts();

            // Try to log in again
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                .exchange()
                .expectStatus().isEqualTo(423);

            // Attempts should not increase
            User userAfter = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            assertThat(userAfter.getFailedLoginAttempts()).isEqualTo(attemptsWhenLocked);
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/login - Validation Errors")
    class ValidationErrors {

        @Test
        @DisplayName("Should return 400 for blank email")
        void shouldRejectBlankEmail() {
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest("", TestData.VALID_PASSWORD))
                .exchange()
                .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should return 400 for blank password")
        void shouldRejectBlankPassword() {
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, ""))
                .exchange()
                .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should return 400 for invalid email format")
        void shouldRejectInvalidEmailFormat() {
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest("not-an-email", TestData.VALID_PASSWORD))
                .exchange()
                .expectStatus().isBadRequest();
        }
    }
}
