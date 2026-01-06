package com.atychkivskyy.authservice.service;

import com.atychkivskyy.authservice.config.JwtConfig;
import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;
import com.atychkivskyy.authservice.security.SecurityUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;

@DisplayName("JwtService")
class JwtServiceTest {

    private JwtService jwtService;

    private static final String TEST_SECRET = "dGhpcy1pcy1hLXZlcnktc2VjdXJlLXNlY3JldC1rZXktZm9yLXRlc3RzCg==";
    private static final String TEST_ISSUER = "auth-service-test";
    private static final long ACCESS_TOKEN_EXPIRATION = 900000L;
    private static final long REFRESH_TOKEN_EXPIRATION = 604800000L;

    @BeforeEach
    void setUp() {
        JwtConfig jwtConfig = new JwtConfig(
            TEST_SECRET,
            ACCESS_TOKEN_EXPIRATION,
            REFRESH_TOKEN_EXPIRATION,
            TEST_ISSUER
        );
        jwtService = new JwtService(jwtConfig);
    }

    private User createUser(String email, String passwordHash, boolean enabled, Set<Role> roles) {
        return User.builder()
            .email(email)
            .passwordHash(passwordHash)
            .firstName("Test")
            .lastName("User")
            .enabled(enabled)
            .roles(roles)
            .build();
    }

    private SecurityUserDetails createUserDetails(String email, String... roleNames) {
        Set<Role> roles = Arrays.stream(roleNames)
            .map(Role::new)
            .collect(Collectors.toSet());

        User user = createUser(email, "hashedPassword", true, roles);
        return new SecurityUserDetails(user);
    }

    private SecurityUserDetails createUserDetails(User user) {
        return new SecurityUserDetails(user);
    }

    @Nested
    @DisplayName("generateAccessToken")
    class GenerateAccessToken {

        @Test
        @DisplayName("Should generate a valid JWT token")
        void shouldGenerateValidJwtToken() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");

            String token = jwtService.generateAccessToken(userDetails);

            assertThat(token)
                .isNotNull()
                .isNotBlank();
            assertThat(token.split("\\.")).hasSize(3);
        }

        @Test
        @DisplayName("Should include username as subject")
        void shouldIncludeUsernameAsSubject() {
            SecurityUserDetails userDetails = createUserDetails("john.doe@example.com", "ROLE_USER");

            String token = jwtService.generateAccessToken(userDetails);

            String extractedUsername = jwtService.extractUsername(token);
            assertThat(extractedUsername).isEqualTo("john.doe@example.com");
        }

        @Test
        @DisplayName("Should include single role in token")
        void shouldIncludeSingleRoleInToken() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");

            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            assertThat(roles).containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("Should include multiple roles in token")
        void shouldIncludeMultipleRolesInToken() {
            SecurityUserDetails userDetails = createUserDetails(
                "admin@example.com",
                "ROLE_USER", "ROLE_ADMIN", "ROLE_MODERATOR"
            );

            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            assertThat(roles).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MODERATOR");
        }

        @Test
        @DisplayName("Should include empty roles list when user has no roles")
        void shouldIncludeEmptyRolesListWhenNoRoles() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com");

            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            assertThat(roles).isEmpty();
        }

        @Test
        @DisplayName("Should include correct issuer")
        void shouldIncludeCorrectIssuer() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");

            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);
            assertThat(claims.getIssuer()).isEqualTo(TEST_ISSUER);
        }

        @Test
        @DisplayName("Should include issuedAt timestamp")
        void shouldIncludeIssuedAtTimestamp() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");
            Date beforeGeneration = truncateToSeconds(new Date());

            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);
            Date issuedAt = claims.getIssuedAt();
            Date afterGeneration = truncateToSeconds(new Date(System.currentTimeMillis() + 1000));

            assertThat(issuedAt)
                .isNotNull()
                .isAfterOrEqualTo(beforeGeneration)
                .isBeforeOrEqualTo(afterGeneration);
        }

        @Test
        @DisplayName("Should include expiration timestamp based on access token expiration")
        void shouldIncludeExpirationTimestamp() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");

            Date beforeGeneration = truncateToSeconds(new Date());

            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);
            Date expiration = claims.getExpiration();

            Date expectedMinExpiration = new Date(beforeGeneration.getTime() + ACCESS_TOKEN_EXPIRATION);
            Date expectedMaxExpiration = truncateToSeconds(
                new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION + 1000)
            );

            assertThat(expiration).isNotNull();
            assertThat(expiration)
                .isAfterOrEqualTo(expectedMinExpiration)
                .isBeforeOrEqualTo(expectedMaxExpiration);
        }

        @Test
        @DisplayName("Should include unique JWT ID (jti)")
        void shouldIncludeUniqueJwtId() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");

            String token1 = jwtService.generateAccessToken(userDetails);
            String token2 = jwtService.generateAccessToken(userDetails);

            Claims claims1 = extractClaims(token1);
            Claims claims2 = extractClaims(token2);

            assertThat(claims1.getId())
                .isNotNull()
                .isNotBlank();
            assertThat(claims2.getId())
                .isNotNull()
                .isNotBlank();
            assertThat(claims1.getId()).isNotEqualTo(claims2.getId());
        }

        @Test
        @DisplayName("Should generate different tokens for same user")
        void shouldGenerateDifferentTokensForSameUser() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");

            String token1 = jwtService.generateAccessToken(userDetails);
            String token2 = jwtService.generateAccessToken(userDetails);

            assertThat(token1).isNotEqualTo(token2);
        }

        @Test
        @DisplayName("Should generate token for disabled user")
        void shouldGenerateTokenForDisabledUser() {
            User disabledUser = User.builder()
                .email("disabled@example.com")
                .passwordHash("hash")
                .firstName("Disabled")
                .lastName("User")
                .enabled(false)
                .roles(Set.of(new Role("ROLE_USER")))
                .build();
            SecurityUserDetails userDetails = createUserDetails(disabledUser);

            String token = jwtService.generateAccessToken(userDetails);

            assertThat(token).isNotBlank();
            assertThat(jwtService.extractUsername(token)).isEqualTo("disabled@example.com");
        }

        @Test
        @DisplayName("Should generate token for locked user")
        void shouldGenerateTokenForLockedUser() {
            User lockedUser = User.builder()
                .email("locked@example.com")
                .passwordHash("hash")
                .firstName("Locked")
                .lastName("User")
                .enabled(true)
                .roles(Set.of(new Role("ROLE_USER")))
                .build();
            lockedUser.lock();
            SecurityUserDetails userDetails = createUserDetails(lockedUser);

            String token = jwtService.generateAccessToken(userDetails);

            assertThat(token).isNotBlank();
            assertThat(jwtService.extractUsername(token)).isEqualTo("locked@example.com");
        }
    }

    @Nested
    @DisplayName("extractUsername")
    class ExtractUsername {

        @Test
        @DisplayName("Should extract username from valid token")
        void shouldExtractUsernameFromValidToken() {
            SecurityUserDetails userDetails = createUserDetails("extract@example.com", "ROLE_USER");
            String token = jwtService.generateAccessToken(userDetails);

            String username = jwtService.extractUsername(token);

            assertThat(username).isEqualTo("extract@example.com");
        }

        @Test
        @DisplayName("Should throw exception for malformed token")
        void shouldThrowExceptionForMalformedToken() {
            assertThatThrownBy(() -> jwtService.extractUsername("not.a.valid.jwt"))
                .isInstanceOf(MalformedJwtException.class);
        }

        @Test
        @DisplayName("Should throw exception for completely invalid token")
        void shouldThrowExceptionForCompletelyInvalidToken() {
            assertThatThrownBy(() -> jwtService.extractUsername("invalid-token"))
                .isInstanceOf(MalformedJwtException.class);
        }

        @Test
        @DisplayName("Should throw exception for token with invalid signature")
        void shouldThrowExceptionForTokenWithInvalidSignature() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");
            String token = jwtService.generateAccessToken(userDetails);
            String tamperedToken = token.substring(0, token.lastIndexOf('.') + 1) + "invalidsignature";

            assertThatThrownBy(() -> jwtService.extractUsername(tamperedToken))
                .isInstanceOf(SignatureException.class);
        }

        @Test
        @DisplayName("Should throw exception for token signed with different key")
        void shouldThrowExceptionForTokenSignedWithDifferentKey() {
            String differentSecret = "YW5vdGhlci12ZXJ5LXNlY3VyZS1zZWNyZXQta2V5LWZvci10ZXN0cwo=";
            SecretKey differentKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(differentSecret));

            String tokenWithDifferentKey = Jwts.builder()
                .subject("user@example.com")
                .issuer(TEST_ISSUER)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION))
                .signWith(differentKey, Jwts.SIG.HS256)
                .compact();

            assertThatThrownBy(() -> jwtService.extractUsername(tokenWithDifferentKey))
                .isInstanceOf(SignatureException.class);
        }

        @Test
        @DisplayName("Should throw exception for token with wrong issuer")
        void shouldThrowExceptionForTokenWithWrongIssuer() {
            SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));

            String tokenWithWrongIssuer = Jwts.builder()
                .subject("user@example.com")
                .issuer("wrong-issuer")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

            assertThatThrownBy(() -> jwtService.extractUsername(tokenWithWrongIssuer))
                .isInstanceOf(io.jsonwebtoken.IncorrectClaimException.class);
        }

        @Test
        @DisplayName("Should throw exception for expired token")
        void shouldThrowExceptionForExpiredToken() {
            SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));

            String expiredToken = Jwts.builder()
                .subject("user@example.com")
                .issuer(TEST_ISSUER)
                .issuedAt(new Date(System.currentTimeMillis() - 3600000))
                .expiration(new Date(System.currentTimeMillis() - 1800000))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

            assertThatThrownBy(() -> jwtService.extractUsername(expiredToken))
                .isInstanceOf(ExpiredJwtException.class);
        }

        @Test
        @DisplayName("Should throw exception for empty token")
        void shouldThrowExceptionForEmptyToken() {
            assertThatThrownBy(() -> jwtService.extractUsername(""))
                .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw exception for null token")
        void shouldThrowExceptionForNullToken() {
            assertThatThrownBy(() -> jwtService.extractUsername(null))
                .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("isTokenValid")
    class IsTokenValid {

        @Test
        @DisplayName("Should return true for valid token and matching user")
        void shouldReturnTrueForValidTokenAndMatchingUser() {
            SecurityUserDetails userDetails = createUserDetails("valid@example.com", "ROLE_USER");
            String token = jwtService.generateAccessToken(userDetails);

            boolean isValid = jwtService.isTokenValid(token, userDetails);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should return false when username does not match")
        void shouldReturnFalseWhenUsernameDoesNotMatch() {
            SecurityUserDetails tokenOwner = createUserDetails("owner@example.com", "ROLE_USER");
            SecurityUserDetails differentUser = createUserDetails("different@example.com", "ROLE_USER");
            String token = jwtService.generateAccessToken(tokenOwner);

            boolean isValid = jwtService.isTokenValid(token, differentUser);

            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return true when roles differ but username matches")
        void shouldReturnTrueWhenRolesDifferButUsernameMatches() {
            SecurityUserDetails originalUser = createUserDetails("user@example.com", "ROLE_USER");
            String token = jwtService.generateAccessToken(originalUser);

            // Same email but different roles
            SecurityUserDetails userWithDifferentRoles = createUserDetails("user@example.com", "ROLE_ADMIN");

            boolean isValid = jwtService.isTokenValid(token, userWithDifferentRoles);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should throw exception for expired token during validation")
        void shouldThrowExceptionForExpiredTokenDuringValidation() {
            SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");

            String expiredToken = Jwts.builder()
                .subject("user@example.com")
                .issuer(TEST_ISSUER)
                .issuedAt(new Date(System.currentTimeMillis() - 3600000))
                .expiration(new Date(System.currentTimeMillis() - 1800000))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

            assertThatThrownBy(() -> jwtService.isTokenValid(expiredToken, userDetails))
                .isInstanceOf(ExpiredJwtException.class);
        }

        @Test
        @DisplayName("Should throw exception for malformed token during validation")
        void shouldThrowExceptionForMalformedTokenDuringValidation() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");

            assertThatThrownBy(() -> jwtService.isTokenValid("invalid-token", userDetails))
                .isInstanceOf(MalformedJwtException.class);
        }

        @Test
        @DisplayName("Should validate token for user with multiple roles")
        void shouldValidateTokenForUserWithMultipleRoles() {
            SecurityUserDetails userDetails = createUserDetails(
                "admin@example.com",
                "ROLE_USER", "ROLE_ADMIN", "ROLE_MODERATOR"
            );
            String token = jwtService.generateAccessToken(userDetails);

            boolean isValid = jwtService.isTokenValid(token, userDetails);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should validate token for user with no roles")
        void shouldValidateTokenForUserWithNoRoles() {
            SecurityUserDetails userDetails = createUserDetails("noroles@example.com");
            String token = jwtService.generateAccessToken(userDetails);

            boolean isValid = jwtService.isTokenValid(token, userDetails);

            assertThat(isValid).isTrue();
        }
    }

    @Nested
    @DisplayName("getAccessTokenExpiration")
    class GetAccessTokenExpiration {

        @Test
        @DisplayName("Should return configured access token expiration time")
        void shouldReturnConfiguredAccessTokenExpirationTime() {
            long expiration = jwtService.getAccessTokenExpiration();

            assertThat(expiration).isEqualTo(ACCESS_TOKEN_EXPIRATION);
        }

        @Test
        @DisplayName("Should return consistent expiration value")
        void shouldReturnConsistentExpirationValue() {
            long expiration1 = jwtService.getAccessTokenExpiration();
            long expiration2 = jwtService.getAccessTokenExpiration();

            assertThat(expiration1).isEqualTo(expiration2);
        }
    }

    @Nested
    @DisplayName("Token Structure Verification")
    class TokenStructureVerification {

        @Test
        @DisplayName("generated token should be parseable")
        void generatedTokenShouldBeParseable() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");
            String token = jwtService.generateAccessToken(userDetails);

            assertThatCode(() -> extractClaims(token)).doesNotThrowAnyException();
        }

        @Test
        @DisplayName("token should contain all required claims")
        void tokenShouldContainAllRequiredClaims() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");
            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);

            assertThat(claims.getSubject()).isNotNull();
            assertThat(claims.getIssuer()).isNotNull();
            assertThat(claims.getIssuedAt()).isNotNull();
            assertThat(claims.getExpiration()).isNotNull();
            assertThat(claims.getId()).isNotNull();
            assertThat(claims.get("roles")).isNotNull();
        }

        @Test
        @DisplayName("token should have correct claim types")
        void tokenShouldHaveCorrectClaimTypes() {
            SecurityUserDetails userDetails = createUserDetails("user@example.com", "ROLE_USER");
            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);

            assertThat(claims.getSubject()).isInstanceOf(String.class);
            assertThat(claims.getIssuer()).isInstanceOf(String.class);
            assertThat(claims.getIssuedAt()).isInstanceOf(Date.class);
            assertThat(claims.getExpiration()).isInstanceOf(Date.class);
            assertThat(claims.getId()).isInstanceOf(String.class);
            assertThat(claims.get("roles")).isInstanceOf(List.class);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("Should handle username with special characters")
        void shouldHandleUsernameWithSpecialCharacters() {
            SecurityUserDetails userDetails = createUserDetails("user+test@example.com", "ROLE_USER");

            String token = jwtService.generateAccessToken(userDetails);
            String extractedUsername = jwtService.extractUsername(token);

            assertThat(extractedUsername).isEqualTo("user+test@example.com");
        }

        @Test
        @DisplayName("Should handle very long username")
        void shouldHandleVeryLongUsername() {
            String longEmail = "a".repeat(200) + "@example.com";
            SecurityUserDetails userDetails = createUserDetails(longEmail, "ROLE_USER");

            String token = jwtService.generateAccessToken(userDetails);
            String extractedUsername = jwtService.extractUsername(token);

            assertThat(extractedUsername).isEqualTo(longEmail);
        }

        @Test
        @DisplayName("Should handle role names with special characters")
        void shouldHandleRoleNamesWithSpecialCharacters() {
            SecurityUserDetails userDetails = createUserDetails(
                "user@example.com",
                "ROLE_USER", "ROLE_ADMIN:SUPER", "ROLE_TEST_USER"
            );

            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            assertThat(roles).containsExactlyInAnyOrder(
                "ROLE_USER", "ROLE_ADMIN:SUPER", "ROLE_TEST_USER"
            );
        }

        @Test
        @DisplayName("Should handle unicode characters in username")
        void shouldHandleUnicodeCharactersInUsername() {
            SecurityUserDetails userDetails = createUserDetails("用户@example.com", "ROLE_USER");

            String token = jwtService.generateAccessToken(userDetails);
            String extractedUsername = jwtService.extractUsername(token);

            assertThat(extractedUsername).isEqualTo("用户@example.com");
        }

        @Test
        @DisplayName("Should handle email with subdomain")
        void shouldHandleEmailWithSubdomain() {
            SecurityUserDetails userDetails = createUserDetails("user@mail.subdomain.example.com", "ROLE_USER");

            String token = jwtService.generateAccessToken(userDetails);
            String extractedUsername = jwtService.extractUsername(token);

            assertThat(extractedUsername).isEqualTo("user@mail.subdomain.example.com");
        }

        @Test
        @DisplayName("Should handle many roles")
        void shouldHandleManyRoles() {
            String[] manyRoles = new String[20];
            for (int i = 0; i < 20; i++) {
                manyRoles[i] = "ROLE_" + i;
            }
            SecurityUserDetails userDetails = createUserDetails("manyroles@example.com", manyRoles);

            String token = jwtService.generateAccessToken(userDetails);

            Claims claims = extractClaims(token);
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            assertThat(roles).hasSize(20);
        }
    }

    @Nested
    @DisplayName("SecurityUserDetails Specific Tests")
    class SecurityUserDetailsSpecificTests {

        @Test
        @DisplayName("Should work with SecurityUserDetails built from User entity")
        void shouldWorkWithSecurityUserDetailsFromUserEntity() {
            Role userRole = new Role("ROLE_USER");
            Role adminRole = new Role("ROLE_ADMIN");

            User user = User.builder()
                .email("entity@example.com")
                .passwordHash("$2a$10$hashedPassword")
                .firstName("Entity")
                .lastName("User")
                .enabled(true)
                .roles(Set.of(userRole, adminRole))
                .build();

            SecurityUserDetails userDetails = new SecurityUserDetails(user);
            String token = jwtService.generateAccessToken(userDetails);

            assertThat(jwtService.extractUsername(token)).isEqualTo("entity@example.com");

            Claims claims = extractClaims(token);
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            assertThat(roles).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
        }

        @Test
        @DisplayName("Should validate token against SecurityUserDetails from same User")
        void shouldValidateTokenAgainstSecurityUserDetailsFromSameUser() {
            User user = User.builder()
                .email("same@example.com")
                .passwordHash("hash")
                .firstName("Same")
                .lastName("User")
                .enabled(true)
                .roles(Set.of(new Role("ROLE_USER")))
                .build();

            SecurityUserDetails userDetails1 = new SecurityUserDetails(user);
            String token = jwtService.generateAccessToken(userDetails1);

            // Create new SecurityUserDetails from same user
            SecurityUserDetails userDetails2 = new SecurityUserDetails(user);

            boolean isValid = jwtService.isTokenValid(token, userDetails2);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("token should be valid regardless of user enabled status change")
        void tokenShouldBeValidRegardlessOfUserEnabledStatusChange() {
            User user = User.builder()
                .email("statuschange@example.com")
                .passwordHash("hash")
                .firstName("Status")
                .lastName("Change")
                .enabled(true)
                .roles(Set.of(new Role("ROLE_USER")))
                .build();

            SecurityUserDetails enabledUserDetails = new SecurityUserDetails(user);
            String token = jwtService.generateAccessToken(enabledUserDetails);

            // Simulate user being disabled after token generation
            user.disable();
            SecurityUserDetails disabledUserDetails = new SecurityUserDetails(user);

            // Token is still valid because validation only checks username and expiry
            boolean isValid = jwtService.isTokenValid(token, disabledUserDetails);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("token should be valid regardless of user lock status change")
        void tokenShouldBeValidRegardlessOfUserLockStatusChange() {
            User user = User.builder()
                .email("lockchange@example.com")
                .passwordHash("hash")
                .firstName("Lock")
                .lastName("Change")
                .enabled(true)
                .roles(Set.of(new Role("ROLE_USER")))
                .build();

            SecurityUserDetails unlockedUserDetails = new SecurityUserDetails(user);
            String token = jwtService.generateAccessToken(unlockedUserDetails);

            // Simulate user being locked after token generation
            user.lock();
            SecurityUserDetails lockedUserDetails = new SecurityUserDetails(user);

            // Token is still valid because validation only checks username and expiry
            boolean isValid = jwtService.isTokenValid(token, lockedUserDetails);

            assertThat(isValid).isTrue();
        }
    }

    // Helper method to extract claims for verification
    private Claims extractClaims(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
        return Jwts.parser()
            .verifyWith(key)
            .requireIssuer(TEST_ISSUER)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    private Date truncateToSeconds(Date date) {
        return new Date((date.getTime() / 1000) * 1000);
    }
}

























