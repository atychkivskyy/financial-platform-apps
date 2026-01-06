package com.atychkivskyy.authservice.e2e;

import com.atychkivskyy.authservice.dto.response.AuthResponse;
import com.atychkivskyy.authservice.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Token Management E2E Tests")
public class TokenE2ETest extends BaseE2ETest {

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
    @DisplayName("GET /api/v1/auth/me - Access Token Validation")
    class AccessTokenValidation {

        @Test
        @DisplayName("Should access protected endpoint with valid token")
        void shouldAccessProtectedEndpointWithValidToken() {
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo(TestData.VALID_EMAIL)
                .jsonPath("$.firstName").isEqualTo(TestData.VALID_FIRST_NAME)
                .jsonPath("$.lastName").isEqualTo(TestData.VALID_LAST_NAME)
                .jsonPath("$.roles").isArray()
                .jsonPath("$.roles[0]").isEqualTo("ROLE_USER");
        }

        @Test
        @DisplayName("Should return 401 without token")
        void shouldRejectRequestWithoutToken() {
            client.get()
                .uri(authUrl("/me"))
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should return 401 with invalid token")
        void shouldRejectRequestWithInvalidToken() {
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer invalid.token.here")
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should return 401 with malformed authorization header")
        void shouldRejectMalformedAuthorizationHeader() {
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "InvalidFormat " + authResponse.accessToken())
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should return 401 with empty bearer token")
        void shouldRejectEmptyBearerToken() {
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer ")
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should return 401 with token from different secret")
        void shouldRejectTokenWithDifferentSecret() {
            // This is a valid JWT format but signed with a different secret
            String tamperedToken = authResponse.accessToken().substring(0, authResponse.accessToken().lastIndexOf('.')) + ".tampered";

            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + tamperedToken)
                .exchange()
                .expectStatus().isUnauthorized();
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/refresh - Refresh Token")
    class RefreshToken {

        @Test
        @DisplayName("Should refresh access token with valid refresh token")
        void shouldRefreshAccessToken() {
            AuthResponse refreshResponse = client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(refreshResponse).isNotNull();
            assertThat(refreshResponse.accessToken()).isNotBlank();
            assertThat(refreshResponse.refreshToken()).isNotBlank();
            assertThat(refreshResponse.tokenType()).isEqualTo("Bearer ");

            // Tokens should be different from original
            assertThat(refreshResponse.accessToken()).isNotEqualTo(authResponse.accessToken());
            assertThat(refreshResponse.refreshToken()).isNotEqualTo(authResponse.refreshToken());
        }

        @Test
        @DisplayName("Should be able to access protected endpoint with new access token")
        void shouldAccessProtectedEndpointWithNewToken() {
            AuthResponse refreshResponse = client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            // Use new access token
            assertThat(refreshResponse).isNotNull();
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + refreshResponse.accessToken())
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo(TestData.VALID_EMAIL);
        }

        @Test
        @DisplayName("Should invalidate old refresh token after use (token rotation)")
        void shouldInvalidateOldRefreshTokenAfterUse() {
            // Use refresh token
            client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isOk();

            // Try to use same refresh token again
            client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should return 401 for invalid refresh token")
        void shouldRejectInvalidRefreshToken() {
            client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest("invalid-refresh-token"))
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should return 400 for blank refresh token")
        void shouldRejectBlankRefreshToken() {
            client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(""))
                .exchange()
                .expectStatus().isBadRequest();
        }

        @Test
        @DisplayName("Should chain multiple refresh operations")
        void shouldChainMultipleRefreshOperations() {
            String currentRefreshToken = authResponse.refreshToken();

            // Refresh 3 times in sequence
            for (int i = 0; i < 3; i++) {
                AuthResponse refreshResponse = client.post()
                    .uri(authUrl("/refresh"))
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(TestData.refreshTokenRequest(currentRefreshToken))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody(AuthResponse.class)
                    .returnResult()
                    .getResponseBody();

                // Update token for next iteration
                assertThat(refreshResponse).isNotNull();
                currentRefreshToken = refreshResponse.refreshToken();

                // Each new token should work
                client.get()
                    .uri(authUrl("/me"))
                    .header("Authorization", "Bearer " + refreshResponse.accessToken())
                    .exchange()
                    .expectStatus().isOk();
            }
        }
    }

    @Nested
    @DisplayName("POST /api/v1/auth/logout - Logout")
    class Logout {

        @Test
        @DisplayName("Should logout successfully")
        void shouldLogoutSuccessfully() {
            client.post()
                .uri(authUrl("/logout"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isNoContent();
        }

        @Test
        @DisplayName("Should invalidate refresh token after logout")
        void shouldInvalidateRefreshTokenAfterLogout() {
            // Logout
            client.post()
                .uri(authUrl("/logout"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isNoContent();

            // Try to use refresh token
            client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isUnauthorized();
        }

        @Test
        @DisplayName("Should still allow access with access token after logout")
        void shouldAllowAccessTokenAfterLogout() {
            // Logout (only revokes refresh token)
            client.post()
                .uri(authUrl("/logout"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isNoContent();

            // Access token should still work (until it expires)
            client.get()
                .uri(authUrl("/me"))
                .header("Authorization", "Bearer " + authResponse.accessToken())
                .exchange()
                .expectStatus().isOk();
        }

        @Test
        @DisplayName("Should handle logout with invalid refresh token gracefully")
        void shouldHandleLogoutWithInvalidTokenGracefully() {
            client.post()
                .uri(authUrl("/logout"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest("invalid-token"))
                .exchange()
                .expectStatus().isNoContent();
        }

        @Test
        @DisplayName("Should handle double logout gracefully")
        void shouldHandleDoubleLogoutGracefully() {
            // First logout
            client.post()
                .uri(authUrl("/logout"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isNoContent();

            // Second logout with same token
            client.post()
                .uri(authUrl("/logout"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isNoContent();
        }
    }

    @Nested
    @DisplayName("Token Persistence")
    class TokenPersistence {

        @Test
        @DisplayName("Should store refresh token in database")
        void shouldStoreRefreshTokenInDatabase() {
            User user = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
            long tokenCount = refreshTokenRepository.countActiveTokensByUserId(
                user.getId(),
                java.time.Instant.now()
            );

            // Should have at least one active token (from login)
            assertThat(tokenCount).isGreaterThanOrEqualTo(1);
        }

        @Test
        @DisplayName("Should mark refresh token as revoked after use")
        void shouldMarkRefreshTokenAsRevokedAfterUse() {
            User user = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();

            // Count before refresh
            long countBefore = refreshTokenRepository.countActiveTokensByUserId(
                user.getId(),
                java.time.Instant.now()
            );

            // Use refresh token
            client.post()
                .uri(authUrl("/refresh"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
                .exchange()
                .expectStatus().isOk();

            // Count should remain same (old revoked, new created)
            long countAfter = refreshTokenRepository.countActiveTokensByUserId(
                user.getId(),
                java.time.Instant.now()
            );

            assertThat(countAfter).isEqualTo(countBefore);
        }
    }
}
