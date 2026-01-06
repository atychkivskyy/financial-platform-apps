package com.atychkivskyy.authservice.security;


import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SecurityUserDetails")
class SecurityUserDetailsTest {
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

    private User createEnabledUser(String email, Set<Role> roles) {
        return createUser(email, "hashedPassword", true, roles);
    }

    @Nested
    @DisplayName("Construction from User")
    class ConstructionFromUser {

        @Test
        @DisplayName("should extract email as username")
        void shouldExtractEmailAsUsername() {
            User user = createEnabledUser("john@example.com", Set.of());

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.getUsername()).isEqualTo("john@example.com");
        }

        @Test
        @DisplayName("should extract password hash as password")
        void shouldExtractPasswordHashAsPassword() {
            User user = User.builder()
                .email("test@example.com")
                .passwordHash("$2a$10$hashedPasswordValue")
                .firstName("Test")
                .lastName("User")
                .build();

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.getPassword()).isEqualTo("$2a$10$hashedPasswordValue");
        }

        @Test
        @DisplayName("should extract enabled status")
        void shouldExtractEnabledStatus() {
            User enabledUser = createUser("enabled@example.com", "hash", true, Set.of());
            User disabledUser = createUser("disabled@example.com", "hash", false, Set.of());

            SecurityUserDetails enabledDetails = new SecurityUserDetails(enabledUser);
            SecurityUserDetails disabledDetails = new SecurityUserDetails(disabledUser);

            assertThat(enabledDetails.isEnabled()).isTrue();
            assertThat(disabledDetails.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("should extract account non locked status")
        void shouldExtractAccountNonLockedStatus() {
            User unlockedUser = createEnabledUser("unlocked@example.com", Set.of());
            User lockedUser = User.builder()
                .email("locked@example.com")
                .passwordHash("hash")
                .firstName("Test")
                .lastName("User")
                .enabled(true)
                .build();
            lockedUser.lock();

            SecurityUserDetails unlockedDetails = new SecurityUserDetails(unlockedUser);
            SecurityUserDetails lockedDetails = new SecurityUserDetails(lockedUser);

            assertThat(unlockedDetails.isAccountNonLocked()).isTrue();
            assertThat(lockedDetails.isAccountNonLocked()).isFalse();
        }
    }

    @Nested
    @DisplayName("User ID")
    class UserId {

        @Test
        @DisplayName("should return user id")
        void shouldReturnUserId() {
            User user = createEnabledUser("test@example.com", Set.of());
            // Note: ID is null until persisted, but we test the getter works

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.getId()).isEqualTo(user.getId());
        }
    }

    @Nested
    @DisplayName("Authorities")
    class Authorities {

        @Test
        @DisplayName("should convert single role to authority")
        void shouldConvertSingleRoleToAuthority() {
            Role userRole = new Role("ROLE_USER");
            User user = createEnabledUser("user@example.com", Set.of(userRole));

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            assertThat(authorities)
                .hasSize(1)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("should convert multiple roles to authorities")
        void shouldConvertMultipleRolesToAuthorities() {
            Role userRole = new Role("ROLE_USER");
            Role adminRole = new Role("ROLE_ADMIN");
            Role moderatorRole = new Role("ROLE_MODERATOR");
            User user = createEnabledUser("admin@example.com", Set.of(userRole, adminRole, moderatorRole));

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            assertThat(authorities)
                .hasSize(3)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MODERATOR");
        }

        @Test
        @DisplayName("should return empty authorities when user has no roles")
        void shouldReturnEmptyAuthoritiesWhenNoRoles() {
            User user = createEnabledUser("noroles@example.com", Set.of());

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.getAuthorities()).isEmpty();
        }

        @Test
        @DisplayName("authorities should not be null")
        void authoritiesShouldNotBeNull() {
            User user = createEnabledUser("test@example.com", Set.of());

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.getAuthorities()).isNotNull();
        }
    }

    @Nested
    @DisplayName("Default Account Status Methods")
    class DefaultAccountStatusMethods {

        @Test
        @DisplayName("isAccountNonExpired should always return true")
        void isAccountNonExpiredShouldAlwaysReturnTrue() {
            User user = createEnabledUser("test@example.com", Set.of());

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.isAccountNonExpired()).isTrue();
        }

        @Test
        @DisplayName("isCredentialsNonExpired should always return true")
        void isCredentialsNonExpiredShouldAlwaysReturnTrue() {
            User user = createEnabledUser("test@example.com", Set.of());

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.isCredentialsNonExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("UserDetails Contract")
    class UserDetailsContract {

        @Test
        @DisplayName("should implement all UserDetails methods")
        void shouldImplementAllUserDetailsMethods() {
            Role role = new Role("ROLE_USER");
            User user = createEnabledUser("contract@example.com", Set.of(role));

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            // Verify all UserDetails methods return non-null or expected values
            assertThat(userDetails.getUsername()).isNotNull();
            assertThat(userDetails.getPassword()).isNotNull();
            assertThat(userDetails.getAuthorities()).isNotNull();
            assertThat(userDetails.isEnabled()).isTrue();
            assertThat(userDetails.isAccountNonLocked()).isTrue();
            assertThat(userDetails.isAccountNonExpired()).isTrue();
            assertThat(userDetails.isCredentialsNonExpired()).isTrue();
        }

        @Test
        @DisplayName("should be usable for authentication decision")
        void shouldBeUsableForAuthenticationDecision() {
            Role role = new Role("ROLE_USER");
            User enabledUnlockedUser = createEnabledUser("active@example.com", Set.of(role));

            SecurityUserDetails userDetails = new SecurityUserDetails(enabledUnlockedUser);

            // An account is fully usable when all these are true
            boolean canAuthenticate = userDetails.isEnabled()
                && userDetails.isAccountNonLocked()
                && userDetails.isAccountNonExpired()
                && userDetails.isCredentialsNonExpired();

            assertThat(canAuthenticate).isTrue();
        }

        @Test
        @DisplayName("disabled user should not be fully authenticatable")
        void disabledUserShouldNotBeFullyAuthenticatable() {
            User disabledUser = createUser("disabled@example.com", "hash", false, Set.of());

            SecurityUserDetails userDetails = new SecurityUserDetails(disabledUser);

            assertThat(userDetails.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("locked user should not be fully authenticatable")
        void lockedUserShouldNotBeFullyAuthenticatable() {
            User lockedUser = User.builder()
                .email("locked@example.com")
                .passwordHash("hash")
                .firstName("Locked")
                .lastName("User")
                .enabled(true)
                .build();
            lockedUser.lock();

            SecurityUserDetails userDetails = new SecurityUserDetails(lockedUser);

            assertThat(userDetails.isAccountNonLocked()).isFalse();
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("should handle user with many roles")
        void shouldHandleUserWithManyRoles() {
            Set<Role> manyRoles = Set.of(
                new Role("ROLE_1"),
                new Role("ROLE_2"),
                new Role("ROLE_3"),
                new Role("ROLE_4"),
                new Role("ROLE_5"),
                new Role("ROLE_6"),
                new Role("ROLE_7"),
                new Role("ROLE_8"),
                new Role("ROLE_9"),
                new Role("ROLE_10")
            );
            User user = createEnabledUser("manyroles@example.com", manyRoles);

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.getAuthorities()).hasSize(10);
        }

        @Test
        @DisplayName("should handle special characters in email")
        void shouldHandleSpecialCharactersInEmail() {
            User user = createEnabledUser("user+tag@sub.example.com", Set.of());

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.getUsername()).isEqualTo("user+tag@sub.example.com");
        }

        @Test
        @DisplayName("should handle role names with special patterns")
        void shouldHandleRoleNamesWithSpecialPatterns() {
            Set<Role> roles = Set.of(
                new Role("ROLE_ADMIN_SUPER"),
                new Role("ROLE_USER:READ"),
                new Role("SCOPE_api.read")
            );
            User user = createEnabledUser("special@example.com", roles);

            SecurityUserDetails userDetails = new SecurityUserDetails(user);

            assertThat(userDetails.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_ADMIN_SUPER", "ROLE_USER:READ", "SCOPE_api.read");
        }
    }
}
