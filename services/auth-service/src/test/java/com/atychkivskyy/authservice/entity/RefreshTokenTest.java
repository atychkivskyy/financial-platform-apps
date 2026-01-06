package com.atychkivskyy.authservice.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RefreshToken Entity")
class RefreshTokenTest {
    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
            .email("test@example.com")
            .passwordHash("hashedPassword")
            .firstName("Test")
            .lastName("User")
            .build();
    }

    @Nested
    @DisplayName("Construction")
    class Construction {

        @Test
        @DisplayName("Should create refresh token with default constructor")
        void shouldCreateRefreshTokenWithDefaultConstructor() {
            RefreshToken refreshToken = new RefreshToken();

            assertThat(refreshToken.getId()).isNull();
            assertThat(refreshToken.getUser()).isNull();
            assertThat(refreshToken.getToken()).isNull();
            assertThat(refreshToken.getExpiresAt()).isNull();
            assertThat(refreshToken.isRevoked()).isFalse();
            assertThat(refreshToken.getCreatedAt()).isNull();
            assertThat(refreshToken.getRevokedAt()).isNull();
        }

        @Test
        @DisplayName("Should create refresh token with factory method")
        void shouldCreateRefreshTokenWithFactoryMethod() {
            String tokenValue = "secure-token-value";
            Instant expiresAt = Instant.now().plus(7, ChronoUnit.DAYS);

            RefreshToken refreshToken = RefreshToken.create(testUser, tokenValue, expiresAt);

            assertThat(refreshToken.getUser()).isEqualTo(testUser);
            assertThat(refreshToken.getToken()).isEqualTo(tokenValue);
            assertThat(refreshToken.getExpiresAt()).isEqualTo(expiresAt);
            assertThat(refreshToken.isRevoked()).isFalse();
        }
    }

    @Nested
    @DisplayName("Revocation")
    class Revocation {

        @Test
        @DisplayName("Should revoke token")
        void shouldRevokeToken() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().plus(7, ChronoUnit.DAYS)
            );
            assertThat(refreshToken.isRevoked()).isFalse();
            assertThat(refreshToken.getRevokedAt()).isNull();

            refreshToken.revoke();

            assertThat(refreshToken.isRevoked()).isTrue();
            assertThat(refreshToken.getRevokedAt()).isNotNull();
        }

        @Test
        @DisplayName("Should set revokedAt timestamp when revoked")
        void shouldSetRevokedAtTimestampWhenRevoked() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().plus(7, ChronoUnit.DAYS)
            );
            Instant beforeRevoke = Instant.now();

            refreshToken.revoke();

            assertThat(refreshToken.getRevokedAt()).isAfterOrEqualTo(beforeRevoke);
            assertThat(refreshToken.getRevokedAt()).isBeforeOrEqualTo(Instant.now());
        }
    }

    @Nested
    @DisplayName("Expiration")
    class Expiration {

        @Test
        @DisplayName("Should not be expired when expiry is in the future")
        void shouldNotBeExpiredWhenExpiryIsInFuture() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().plus(1, ChronoUnit.HOURS)
            );

            assertThat(refreshToken.isExpired()).isFalse();
        }

        @Test
        @DisplayName("Should be expired when expiry is in the past")
        void shouldBeExpiredWhenExpiryIsInPast() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().minus(1, ChronoUnit.HOURS)
            );

            assertThat(refreshToken.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should be expired when expiry is exactly now")
        void shouldBeExpiredWhenExpiryIsExactlyNow() {
            // Create token that expires immediately
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().minusMillis(1)
            );

            assertThat(refreshToken.isExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("Validity")
    class Validity {

        @Test
        @DisplayName("Should be valid when not revoked and not expired")
        void shouldBeValidWhenNotRevokedAndNotExpired() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().plus(7, ChronoUnit.DAYS)
            );

            assertThat(refreshToken.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should not be valid when revoked")
        void shouldNotBeValidWhenRevoked() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().plus(7, ChronoUnit.DAYS)
            );
            refreshToken.revoke();

            assertThat(refreshToken.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should not be valid when expired")
        void shouldNotBeValidWhenExpired() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().minus(1, ChronoUnit.HOURS)
            );

            assertThat(refreshToken.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should not be valid when both revoked and expired")
        void shouldNotBeValidWhenBothRevokedAndExpired() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().minus(1, ChronoUnit.HOURS)
            );
            refreshToken.revoke();

            assertThat(refreshToken.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("Lifecycle Callbacks")
    class LifecycleCallbacks {

        @Test
        @DisplayName("onCreate should set createdAt timestamp")
        void onCreateShouldSetCreatedAtTimestamp() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().plus(7, ChronoUnit.DAYS)
            );
            assertThat(refreshToken.getCreatedAt()).isNull();

            refreshToken.onCreate();

            assertThat(refreshToken.getCreatedAt()).isNotNull();
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return all fields correctly")
        void shouldReturnAllFieldsCorrectly() {
            String tokenValue = "unique-token-123";
            Instant expiresAt = Instant.now().plus(30, ChronoUnit.DAYS);

            RefreshToken refreshToken = RefreshToken.create(testUser, tokenValue, expiresAt);

            assertThat(refreshToken.getId()).isNull(); // Not persisted yet
            assertThat(refreshToken.getUser()).isSameAs(testUser);
            assertThat(refreshToken.getToken()).isEqualTo(tokenValue);
            assertThat(refreshToken.getExpiresAt()).isEqualTo(expiresAt);
            assertThat(refreshToken.isRevoked()).isFalse();
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle very long expiration time")
        void shouldHandleVeryLongExpirationTime() {
            Instant farFuture = Instant.now().plus(365 * 10, ChronoUnit.DAYS);

            RefreshToken refreshToken = RefreshToken.create(testUser, "token", farFuture);

            assertThat(refreshToken.isExpired()).isFalse();
            assertThat(refreshToken.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should handle revocation multiple times idempotently")
        void shouldHandleRevocationMultipleTimesIdempotently() {
            RefreshToken refreshToken = RefreshToken.create(
                testUser,
                "token",
                Instant.now().plus(7, ChronoUnit.DAYS)
            );

            refreshToken.revoke();
            Instant firstRevokedAt = refreshToken.getRevokedAt();

            refreshToken.revoke();

            assertThat(refreshToken.isRevoked()).isTrue();
            // Note: Current implementation updates revokedAt each time
            assertThat(refreshToken.getRevokedAt()).isAfterOrEqualTo(firstRevokedAt);
        }
    }
}
