package com.atychkivskyy.authservice.e2e;

import com.atychkivskyy.authservice.dto.response.AuthResponse;
import com.atychkivskyy.authservice.dto.response.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("User Profile and Session Management E2E Tests")
class UserProfileE2ETest extends BaseE2ETest {

    private AuthResponse authResponse;

    @BeforeEach
    void registerAndLogin() {
        // Register
        client.post()
            .uri(authUrl("/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validRegisterRequest())
            .exchange()
            .expectStatus().isCreated();

        // Login
        authResponse = client.post()
            .uri(authUrl("/login"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validLoginRequest())
            .exchange()
            .expectStatus().isOk()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();
    }

    @Nested
    @DisplayName("GET /api/v1/auth/me - Get Current User")
    class GetCurrentUser {

        @Test
        @DisplayName("should return complete user profile")
        void shouldReturnCompleteUserProfile() {
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isNotEmpty()
                .jsonPath("$.email").isEqualTo(TestData.VALID_EMAIL)
                .jsonPath("$.firstName").isEqualTo(TestData.VALID_FIRST_NAME)
                .jsonPath("$.lastName").isEqualTo(TestData.VALID_LAST_NAME)
                .jsonPath("$.roles").isArray()
                .jsonPath("$.roles[0]").isEqualTo("ROLE_USER");
        }

        @Test
        @DisplayName("should return user with correct ID from token")
        void shouldReturnUserWithCorrectIdFromToken() {
            UserResponse response = client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isOk()
                .expectBody(UserResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.id()).isEqualTo(authResponse.user().id());
        }

        @Test
        @DisplayName("should return 401 without token")
        void shouldReturn401WithoutToken() {
            client.get()
                .uri(authUrl("/me"))
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("should return 401 with invalid token")
        void shouldReturn401WithInvalidToken() {
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer invalid.token.here")
                .exchange()
                .expectStatus().isUnauthorized();
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/logout-all - Logout All Devices")
    class LogoutAllDevices {

        @Test
        @DisplayName("should logout from all devices successfully")
        void shouldLogoutFromAllDevicesSuccessfully() {
            client.post()
                .uri(authUrl("/logout-all"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isNoContent();
        }

        @Test
        @DisplayName("should invalidate all refresh tokens after logout-all")
        void shouldInvalidateAllRefreshTokensAfterLogoutAll() {
            // Login again to get second session
            AuthResponse secondSession = client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validLoginRequest())
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(secondSession).isNotNull();

            // Logout all devices using first session's access token
            client.post()
                .uri(authUrl("/logout-all"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isNoContent();

            // First session's refresh token should be invalid
            client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isUnauthorized();

            // Second session's refresh token should also be invalid
            client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(secondSession.refreshToken()))
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("should still allow access with current access token after logout-all")
        void shouldStillAllowAccessWithCurrentAccessTokenAfterLogoutAll() {
            // Logout all devices
            client.post()
                .uri(authUrl("/logout-all"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isNoContent();

            // Access token should still work (until it expires naturally)
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isOk();
        }

        @Test
        @DisplayName("should return 401 without authentication")
        void shouldReturn401WithoutAuthentication() {
            client.post()
                .uri(authUrl("/logout-all"))
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("should return 401 with invalid token")
        void shouldReturn401WithInvalidToken() {
            client.post()
                .uri(authUrl("/logout-all"))
                .header("Authorization", "Bearer invalid.token")
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("should allow re-login after logout-all")
        void shouldAllowReLoginAfterLogoutAll() {
            // Logout all
            client.post()
                .uri(authUrl("/logout-all"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isNoContent();

            // Login again should work
            AuthResponse newSession = client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.validLoginRequest())
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(newSession).isNotNull();
            assertThat(newSession.accessToken()).isNotBlank();

            // New session should work
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + newSession.accessToken())
                .exchange()
                .expectStatus().isOk();
        }
    }

    @Nested
    @DisplayName("Multiple Sessions Scenarios")
    class MultipleSessionsScenarios {

        @Test
        @DisplayName("should track multiple active sessions")
        void shouldTrackMultipleActiveSessions() {
            // Create 3 sessions
            for (int i = 0; i < 3; i++) {
                AuthResponse session = client.post()
                    .uri(authUrl("/login"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.validLoginRequest())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(AuthResponse.class)
                    .returnResult()
                    .getResponseBody();

                assertThat(session).isNotNull();
                assertThat(session.accessToken()).isNotBlank();
            }

            // Verify user still exists and is accessible
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isOk();
        }

        @Test
        @DisplayName("should handle logout-all with many active sessions")
        void shouldHandleLogoutAllWithManyActiveSessions() {
            // Create multiple sessions
            AuthResponse[] sessions = new AuthResponse[4];
            for (int i = 0; i < sessions.length; i++) {
                sessions[i] = client.post()
                    .uri(authUrl("/login"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.validLoginRequest())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(AuthResponse.class)
                    .returnResult()
                    .getResponseBody();
            }

            // Logout all
            client.post()
                .uri(authUrl("/logout-all"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isNoContent();

            // All refresh tokens should be invalid
            for (AuthResponse session : sessions) {
                assertThat(session).isNotNull();
                client.post()
                    .uri(authUrl("/refresh"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.refreshTokenRequest(session.refreshToken()))
                    .exchange()
                    .expectStatus().isUnauthorized();
            }
        }
    }
}
