package com.atychkivskyy.authservice.config;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtConfig")
class JwtConfigTest {

    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Nested
    @DisplayName("Validation")
    class ValidationTests {

        @Test
        @DisplayName("should pass validation with all valid values")
        void shouldPassValidationWithAllValidValues() {
            JwtConfig config = new JwtConfig(
                "validSecret123",
                900000L,
                604800000L,
                "test-issuer"
            );

            Set<ConstraintViolation<JwtConfig>> violations = validator.validate(config);

            assertThat(violations).isEmpty();
        }

        @Test
        @DisplayName("should fail validation when secret is blank")
        void shouldFailValidationWhenSecretIsBlank() {
            JwtConfig config = new JwtConfig(
                "",
                900000L,
                604800000L,
                "test-issuer"
            );

            Set<ConstraintViolation<JwtConfig>> violations = validator.validate(config);

            assertThat(violations)
                .hasSize(1)
                .extracting(ConstraintViolation::getMessage)
                .containsExactly("JWT secret is required");
        }

        @Test
        @DisplayName("should fail validation when secret is null")
        void shouldFailValidationWhenSecretIsNull() {
            JwtConfig config = new JwtConfig(
                null,
                900000L,
                604800000L,
                "test-issuer"
            );

            Set<ConstraintViolation<JwtConfig>> violations = validator.validate(config);

            assertThat(violations)
                .hasSize(1)
                .extracting(ConstraintViolation::getMessage)
                .containsExactly("JWT secret is required");
        }

        @Test
        @DisplayName("should fail validation when access token expiration is zero")
        void shouldFailValidationWhenAccessTokenExpirationIsZero() {
            JwtConfig config = new JwtConfig(
                "validSecret",
                0L,
                604800000L,
                "test-issuer"
            );

            Set<ConstraintViolation<JwtConfig>> violations = validator.validate(config);

            assertThat(violations)
                .hasSize(1)
                .extracting(ConstraintViolation::getMessage)
                .containsExactly("Access token expiration must be positive");
        }

        @Test
        @DisplayName("should fail validation when access token expiration is negative")
        void shouldFailValidationWhenAccessTokenExpirationIsNegative() {
            JwtConfig config = new JwtConfig(
                "validSecret",
                -1000L,
                604800000L,
                "test-issuer"
            );

            Set<ConstraintViolation<JwtConfig>> violations = validator.validate(config);

            assertThat(violations)
                .hasSize(1)
                .extracting(ConstraintViolation::getMessage)
                .containsExactly("Access token expiration must be positive");
        }

        @Test
        @DisplayName("should fail validation when refresh token expiration is zero")
        void shouldFailValidationWhenRefreshTokenExpirationIsZero() {
            JwtConfig config = new JwtConfig(
                "validSecret",
                900000L,
                0L,
                "test-issuer"
            );

            Set<ConstraintViolation<JwtConfig>> violations = validator.validate(config);

            assertThat(violations)
                .hasSize(1)
                .extracting(ConstraintViolation::getMessage)
                .containsExactly("Refresh token expiration must be positive");
        }

        @Test
        @DisplayName("should fail validation when refresh token expiration is negative")
        void shouldFailValidationWhenRefreshTokenExpirationIsNegative() {
            JwtConfig config = new JwtConfig(
                "validSecret",
                900000L,
                -5000L,
                "test-issuer"
            );

            Set<ConstraintViolation<JwtConfig>> violations = validator.validate(config);

            assertThat(violations)
                .hasSize(1)
                .extracting(ConstraintViolation::getMessage)
                .containsExactly("Refresh token expiration must be positive");
        }

        @Test
        @DisplayName("should collect multiple validation errors")
        void shouldCollectMultipleValidationErrors() {
            JwtConfig config = new JwtConfig(
                "",
                0L,
                -100L,
                ""
            );

            Set<ConstraintViolation<JwtConfig>> violations = validator.validate(config);

            // Note: issuer gets default value, so only 3 violations
            assertThat(violations).hasSize(3);
        }
    }

    @Nested
    @DisplayName("Default Values")
    class DefaultValueTests {

        @Test
        @DisplayName("should use default issuer when null is provided")
        void shouldUseDefaultIssuerWhenNullIsProvided() {
            JwtConfig config = new JwtConfig(
                "validSecret",
                900000L,
                604800000L,
                null
            );

            assertThat(config.issuer()).isEqualTo("finplatform-auth-service");
        }

        @Test
        @DisplayName("should use default issuer when blank is provided")
        void shouldUseDefaultIssuerWhenBlankIsProvided() {
            JwtConfig config = new JwtConfig(
                "validSecret",
                900000L,
                604800000L,
                ""
            );

            assertThat(config.issuer()).isEqualTo("finplatform-auth-service");
        }

        @Test
        @DisplayName("should use default issuer when whitespace is provided")
        void shouldUseDefaultIssuerWhenWhitespaceIsProvided() {
            JwtConfig config = new JwtConfig(
                "validSecret",
                900000L,
                604800000L,
                "   "
            );

            assertThat(config.issuer()).isEqualTo("finplatform-auth-service");
        }

        @Test
        @DisplayName("should use provided issuer when valid")
        void shouldUseProvidedIssuerWhenValid() {
            JwtConfig config = new JwtConfig(
                "validSecret",
                900000L,
                604800000L,
                "custom-issuer"
            );

            assertThat(config.issuer()).isEqualTo("custom-issuer");
        }
    }

    @Nested
    @DisplayName("Record Accessors")
    class RecordAccessorTests {

        @Test
        @DisplayName("should return all configured values correctly")
        void shouldReturnAllConfiguredValuesCorrectly() {
            JwtConfig config = new JwtConfig(
                "mySecret",
                15000L,
                30000L,
                "my-issuer"
            );

            assertThat(config.secret()).isEqualTo("mySecret");
            assertThat(config.accessTokenExpiration()).isEqualTo(15000L);
            assertThat(config.refreshTokenExpiration()).isEqualTo(30000L);
            assertThat(config.issuer()).isEqualTo("my-issuer");
        }
    }

    @Nested
    @DisplayName("Record Equality")
    class RecordEqualityTests {

        @Test
        @DisplayName("should be equal when all fields are the same")
        void shouldBeEqualWhenAllFieldsAreSame() {
            JwtConfig config1 = new JwtConfig("secret", 1000L, 2000L, "issuer");
            JwtConfig config2 = new JwtConfig("secret", 1000L, 2000L, "issuer");

            assertThat(config1).isEqualTo(config2);
            assertThat(config1.hashCode()).isEqualTo(config2.hashCode());
        }

        @Test
        @DisplayName("should not be equal when fields differ")
        void shouldNotBeEqualWhenFieldsDiffer() {
            JwtConfig config1 = new JwtConfig("secret1", 1000L, 2000L, "issuer");
            JwtConfig config2 = new JwtConfig("secret2", 1000L, 2000L, "issuer");

            assertThat(config1).isNotEqualTo(config2);
        }

        @Test
        @DisplayName("should be equal when both use default issuer")
        void shouldBeEqualWhenBothUseDefaultIssuer() {
            JwtConfig config1 = new JwtConfig("secret", 1000L, 2000L, null);
            JwtConfig config2 = new JwtConfig("secret", 1000L, 2000L, "");

            assertThat(config1).isEqualTo(config2);
        }
    }
}
