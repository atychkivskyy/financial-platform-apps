package com.atychkivskyy.authservice.e2e;

import com.atychkivskyy.authservice.dto.request.RegisterRequest;
import com.atychkivskyy.authservice.dto.response.AuthResponse;
import com.atychkivskyy.authservice.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Full Authentication Flow E2E Tests")
class FullFlowE2ETest extends BaseE2ETest {

    @Test
    @DisplayName("Complete authentication lifecycle: register -> login -> access -> refresh -> logout")
    void shouldCompleteFullAuthenticationLifecycle() {
        // ============================================================
        // Step 1: Register
        // ============================================================
        AuthResponse registerResponse = client.post()
            .uri(authUrl("/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validRegisterRequest())
            .exchange()
            .expectStatus().isCreated()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        assertThat(registerResponse).isNotNull();
        assertThat(registerResponse.accessToken()).isNotBlank();
        assertThat(registerResponse.refreshToken()).isNotBlank();

        // Verify user created in database
        User registeredUser = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
        assertThat(registeredUser.isEnabled()).isTrue();
        assertThat(registeredUser.isAccountNonLocked()).isTrue();

        // ============================================================
        // Step 2: Access protected resource after registration
        // ============================================================
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + registerResponse.accessToken())
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.email").isEqualTo(TestData.VALID_EMAIL);

        // ============================================================
        // Step 3: Login
        // ============================================================
        AuthResponse loginResponse = client.post()
            .uri(authUrl("/login"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validLoginRequest())
            .exchange()
            .expectStatus().isOk()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        assertThat(loginResponse).isNotNull();
        assertThat(loginResponse.accessToken()).isNotEqualTo(registerResponse.accessToken());

        // ============================================================
        // Step 4: Access protected resource after login
        // ============================================================
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + loginResponse.accessToken())
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.email").isEqualTo(TestData.VALID_EMAIL);

        // ============================================================
        // Step 5: Refresh token
        // ============================================================
        AuthResponse refreshResponse = client.post()
            .uri(authUrl("/refresh"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.refreshTokenRequest(loginResponse.refreshToken()))
            .exchange()
            .expectStatus().isOk()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        assertThat(refreshResponse).isNotNull();
        assertThat(refreshResponse.accessToken()).isNotEqualTo(loginResponse.accessToken());
        assertThat(refreshResponse.refreshToken()).isNotEqualTo(loginResponse.refreshToken());

        // ============================================================
        // Step 6: Access protected resource with new token
        // ============================================================
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + refreshResponse.accessToken())
            .exchange()
            .expectStatus().isOk();

        // ============================================================
        // Step 7: Old refresh token should be invalid (token rotation)
        // ============================================================
        client.post()
            .uri(authUrl("/refresh"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.refreshTokenRequest(loginResponse.refreshToken()))
            .exchange()
            .expectStatus().isUnauthorized();

        // ============================================================
        // Step 8: Logout
        // ============================================================
        client.post()
            .uri(authUrl("/logout"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.refreshTokenRequest(refreshResponse.refreshToken()))
            .exchange()
            .expectStatus().isNoContent();

        // ============================================================
        // Step 9: Refresh token should be invalid after logout
        // ============================================================
        client.post()
            .uri(authUrl("/refresh"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.refreshTokenRequest(refreshResponse.refreshToken()))
            .exchange()
            .expectStatus().isUnauthorized();

        // ============================================================
        // Step 10: Access token still works (until expiry)
        // ============================================================
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + refreshResponse.accessToken())
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    @DisplayName("Multiple users should have isolated sessions")
    void shouldIsolateUserSessions() {
        // Register and login User 1
        RegisterRequest user1Request = new RegisterRequest(
            "user1@example.com",
            TestData.VALID_PASSWORD,
            "User",
            "One"
        );

        AuthResponse user1Auth = client.post()
            .uri(authUrl("/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(user1Request)
            .exchange()
            .expectStatus().isCreated()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        // Register and login User 2
        RegisterRequest user2Request = new RegisterRequest(
            "user2@example.com",
            TestData.VALID_PASSWORD,
            "User",
            "Two"
        );

        AuthResponse user2Auth = client.post()
            .uri(authUrl("/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(user2Request)
            .exchange()
            .expectStatus().isCreated()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        // User 1's token should return User 1's data
        assertThat(user1Auth).isNotNull();
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + user1Auth.accessToken())
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.email").isEqualTo("user1@example.com")
            .jsonPath("$.firstName").isEqualTo("User")
            .jsonPath("$.lastName").isEqualTo("One");

        // User 2's token should return User 2's data
        assertThat(user2Auth).isNotNull();
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + user2Auth.accessToken())
            .exchange()
            .expectStatus().isOk()
            .expectBody()
            .jsonPath("$.email").isEqualTo("user2@example.com")
            .jsonPath("$.firstName").isEqualTo("User")
            .jsonPath("$.lastName").isEqualTo("Two");

        // Logout User 1
        client.post()
            .uri(authUrl("/logout"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.refreshTokenRequest(user1Auth.refreshToken()))
            .exchange()
            .expectStatus().isNoContent();

        // User 2 should still be able to refresh
        client.post()
            .uri(authUrl("/refresh"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.refreshTokenRequest(user2Auth.refreshToken()))
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    @DisplayName("Failed login should not affect valid sessions")
    void failedLoginShouldNotAffectValidSessions() {
        // Register and login
        AuthResponse authResponse = client.post()
            .uri(authUrl("/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validRegisterRequest())
            .exchange()
            .expectStatus().isCreated()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        // Failed login attempt
        client.post()
            .uri(authUrl("/login"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
            .exchange()
            .expectStatus().isUnauthorized();

        // Original session should still work
        assertThat(authResponse).isNotNull();
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + authResponse.accessToken())
            .exchange()
            .expectStatus().isOk();

        // Refresh should still work
        client.post()
            .uri(authUrl("/refresh"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    @DisplayName("Account lock should not revoke existing tokens")
    void accountLockShouldNotRevokeExistingTokens() {
        // Register and login
        AuthResponse authResponse = client.post()
            .uri(authUrl("/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validRegisterRequest())
            .exchange()
            .expectStatus().isCreated()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        // Lock the account with failed attempts
        for (int i = 0; i < 5; i++) {
            client.post()
                .uri(authUrl("/login"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(TestData.loginRequest(TestData.VALID_EMAIL, "WrongPassword1!"))
                .exchange();
        }

        // Verify account is locked
        User lockedUser = userRepository.findByEmail(TestData.VALID_EMAIL).orElseThrow();
        assertThat(lockedUser.isAccountNonLocked()).isFalse();

        // Existing access token should still work
        assertThat(authResponse).isNotNull();
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + authResponse.accessToken())
            .exchange()
            .expectStatus().isOk();

        // Existing refresh token should still work
        client.post()
            .uri(authUrl("/refresh"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.refreshTokenRequest(authResponse.refreshToken()))
            .exchange()
            .expectStatus().isOk();
    }

    @Test
    @DisplayName("Concurrent logins should each get unique tokens")
    void concurrentLoginsShouldGetUniqueTokens() {
        // Register
        client.post()
            .uri(authUrl("/register"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validRegisterRequest())
            .exchange()
            .expectStatus().isCreated();

        // Multiple logins (simulating different devices)
        AuthResponse login1 = client.post()
            .uri(authUrl("/login"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validLoginRequest())
            .exchange()
            .expectStatus().isOk()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        AuthResponse login2 = client.post()
            .uri(authUrl("/login"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validLoginRequest())
            .exchange()
            .expectStatus().isOk()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        AuthResponse login3 = client.post()
            .uri(authUrl("/login"))
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(TestData.validLoginRequest())
            .exchange()
            .expectStatus().isOk()
            .expectBody(AuthResponse.class)
            .returnResult()
            .getResponseBody();

        // All tokens should be unique
        assertThat(login1).isNotNull();
        assertThat(login2).isNotNull();
        assertThat(login3).isNotNull();
        assertThat(login1.accessToken())
            .isNotEqualTo(login2.accessToken())
            .isNotEqualTo(login3.accessToken());

        assertThat(login1.refreshToken())
            .isNotEqualTo(login2.refreshToken())
            .isNotEqualTo(login3.refreshToken());

        // All sessions should work independently
        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + login1.accessToken())
            .exchange()
            .expectStatus().isOk();

        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + login2.accessToken())
            .exchange()
            .expectStatus().isOk();

        client.get()
            .uri(authUrl("/me"))
            .header("Authorization", "Bearer " + login3.accessToken())
            .exchange()
            .expectStatus().isOk();
    }
}
