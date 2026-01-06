package com.atychkivskyy.authservice.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("User Entity")
class UserTest {

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
            .email("john.doe@example.com")
            .passwordHash("hashedPassword123")
            .firstName("John")
            .lastName("Doe")
            .build();
    }

    @Nested
    @DisplayName("Builder")
    class BuilderTests {

        @Test
        @DisplayName("should build user with all fields")
        void shouldBuildUserWithAllFields() {
            Role adminRole = new Role("ROLE_ADMIN");

            User builtUser = User.builder()
                .email("jane.doe@example.com")
                .passwordHash("secureHash")
                .firstName("Jane")
                .lastName("Doe")
                .enabled(false)
                .roles(Set.of(adminRole))
                .build();

            assertThat(builtUser.getEmail()).isEqualTo("jane.doe@example.com");
            assertThat(builtUser.getPasswordHash()).isEqualTo("secureHash");
            assertThat(builtUser.getFirstName()).isEqualTo("Jane");
            assertThat(builtUser.getLastName()).isEqualTo("Doe");
            assertThat(builtUser.isEnabled()).isFalse();
            assertThat(builtUser.getRoles()).containsExactly(adminRole);
        }

        @Test
        @DisplayName("should have default values for enabled and accountNonLocked")
        void shouldHaveDefaultValues() {
            User builtUser = User.builder()
                .email("test@example.com")
                .build();

            assertThat(builtUser.isEnabled()).isTrue();
            assertThat(builtUser.isAccountNonLocked()).isTrue();
            assertThat(builtUser.getFailedLoginAttempts()).isZero();
        }
    }

    @Nested
    @DisplayName("Login Attempt Tracking")
    class LoginAttemptTracking {

        @Test
        @DisplayName("should increment failed login attempts")
        void shouldIncrementFailedLoginAttempts() {
            assertThat(user.getFailedLoginAttempts()).isZero();

            user.incrementFailedLoginAttempts();

            assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
        }

        @Test
        @DisplayName("should increment failed login attempts multiple times")
        void shouldIncrementFailedLoginAttemptsMultipleTimes() {
            user.incrementFailedLoginAttempts();
            user.incrementFailedLoginAttempts();
            user.incrementFailedLoginAttempts();

            assertThat(user.getFailedLoginAttempts()).isEqualTo(3);
        }
    }

    @Nested
    @DisplayName("Account Locking")
    class AccountLocking {

        @Test
        @DisplayName("should lock account")
        void shouldLockAccount() {
            assertThat(user.isAccountNonLocked()).isTrue();
            assertThat(user.getLockTime()).isNull();

            user.lock();

            assertThat(user.isAccountNonLocked()).isFalse();
            assertThat(user.getLockTime()).isNotNull();
        }

        @Test
        @DisplayName("should unlock account and reset state")
        void shouldUnlockAccountAndResetState() {
            user.incrementFailedLoginAttempts();
            user.incrementFailedLoginAttempts();
            user.lock();

            user.unlock();

            assertThat(user.isAccountNonLocked()).isTrue();
            assertThat(user.getFailedLoginAttempts()).isZero();
            assertThat(user.getLockTime()).isNull();
        }

        @Test
        @DisplayName("resetFailedLoginAttempts should behave like unlock")
        void resetFailedLoginAttemptsShouldBehaveLikeUnlock() {
            user.incrementFailedLoginAttempts();
            user.lock();

            user.resetFailedLoginAttempts();

            assertThat(user.isAccountNonLocked()).isTrue();
            assertThat(user.getFailedLoginAttempts()).isZero();
            assertThat(user.getLockTime()).isNull();
        }
    }

    @Nested
    @DisplayName("Account Enable/Disable")
    class AccountEnableDisable {

        @Test
        @DisplayName("should disable account")
        void shouldDisableAccount() {
            assertThat(user.isEnabled()).isTrue();

            user.disable();

            assertThat(user.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("should enable account")
        void shouldEnableAccount() {
            user.disable();

            user.enable();

            assertThat(user.isEnabled()).isTrue();
        }
    }

    @Nested
    @DisplayName("Password Update")
    class PasswordUpdate {

        @Test
        @DisplayName("should update password hash")
        void shouldUpdatePasswordHash() {
            String newPasswordHash = "newSecureHashedPassword";

            user.updatePassword(newPasswordHash);

            assertThat(user.getPasswordHash()).isEqualTo(newPasswordHash);
        }

        @Test
        @DisplayName("should throw exception when password hash is null")
        void shouldThrowExceptionWhenPasswordHashIsNull() {
            assertThatThrownBy(() -> user.updatePassword(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("newPasswordHash is required");
        }
    }

    @Nested
    @DisplayName("Profile Update")
    class ProfileUpdate {

        @Test
        @DisplayName("should update profile")
        void shouldUpdateProfile() {
            user.updateProfile("Jane", "Smith");

            assertThat(user.getFirstName()).isEqualTo("Jane");
            assertThat(user.getLastName()).isEqualTo("Smith");
        }

        @Test
        @DisplayName("should throw exception when first name is null")
        void shouldThrowExceptionWhenFirstNameIsNull() {
            assertThatThrownBy(() -> user.updateProfile(null, "Smith"))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("should throw exception when last name is null")
        void shouldThrowExceptionWhenLastNameIsNull() {
            assertThatThrownBy(() -> user.updateProfile("Jane", null))
                .isInstanceOf(NullPointerException.class);
        }
    }

    @Nested
    @DisplayName("Role Management")
    class RoleManagement {

        @Test
        @DisplayName("should assign role")
        void shouldAssignRole() {
            Role adminRole = new Role("ROLE_ADMIN");

            user.assignRole(adminRole);

            assertThat(user.getRoles()).contains(adminRole);
        }

        @Test
        @DisplayName("should throw exception when assigning null role")
        void shouldThrowExceptionWhenAssigningNullRole() {
            assertThatThrownBy(() -> user.assignRole(null))
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("should remove role")
        void shouldRemoveRole() {
            Role adminRole = new Role("ROLE_ADMIN");
            user.assignRole(adminRole);

            user.removeRole(adminRole);

            assertThat(user.getRoles()).doesNotContain(adminRole);
        }

        @Test
        @DisplayName("should not fail when removing non-existent role")
        void shouldNotFailWhenRemovingNonExistentRole() {
            Role adminRole = new Role("ROLE_ADMIN");

            user.removeRole(adminRole);

            assertThat(user.getRoles()).isEmpty();
        }

        @Test
        @DisplayName("should check if user has role")
        void shouldCheckIfUserHasRole() {
            user.assignRole(new Role("ROLE_USER"));

            assertThat(user.hasRole("ROLE_USER")).isTrue();
            assertThat(user.hasRole("ROLE_ADMIN")).isFalse();
        }

        @Test
        @DisplayName("should handle multiple roles")
        void shouldHandleMultipleRoles() {
            user.assignRole(new Role("ROLE_USER"));
            user.assignRole(new Role("ROLE_ADMIN"));
            user.assignRole(new Role("ROLE_MODERATOR"));

            assertThat(user.getRoles()).hasSize(3);
            assertThat(user.hasRole("ROLE_USER")).isTrue();
            assertThat(user.hasRole("ROLE_ADMIN")).isTrue();
            assertThat(user.hasRole("ROLE_MODERATOR")).isTrue();
        }

        @Test
        @DisplayName("should not duplicate same role")
        void shouldNotDuplicateSameRole() {
            user.assignRole(new Role("ROLE_USER"));
            user.assignRole(new Role("ROLE_USER"));

            assertThat(user.getRoles()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("Full Name")
    class FullName {

        @Test
        @DisplayName("should return full name")
        void shouldReturnFullName() {
            assertThat(user.getFullName()).isEqualTo("John Doe");
        }

        @Test
        @DisplayName("should return full name after profile update")
        void shouldReturnFullNameAfterProfileUpdate() {
            user.updateProfile("Jane", "Smith");

            assertThat(user.getFullName()).isEqualTo("Jane Smith");
        }
    }

    @Nested
    @DisplayName("Lifecycle Callbacks")
    class LifecycleCallbacks {

        @Test
        @DisplayName("onCreate should set timestamps")
        void onCreateShouldSetTimestamps() {
            assertThat(user.getCreatedAt()).isNull();
            assertThat(user.getUpdatedAt()).isNull();

            user.onCreate();

            assertThat(user.getCreatedAt()).isNotNull();
            assertThat(user.getUpdatedAt()).isNotNull();
            assertThat(user.getCreatedAt()).isEqualTo(user.getUpdatedAt());
        }

        @Test
        @DisplayName("onUpdate should update updatedAt timestamp")
        void onUpdateShouldUpdateTimestamp() throws InterruptedException {
            user.onCreate();
            var originalUpdatedAt = user.getUpdatedAt();

            Thread.sleep(10); // Ensure time difference
            user.onUpdate();

            assertThat(user.getUpdatedAt()).isAfter(originalUpdatedAt);
            assertThat(user.getCreatedAt()).isNotEqualTo(user.getUpdatedAt());
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Contract")
    class EqualsAndHashCode {

        @Test
        @DisplayName("should be equal to itself")
        void shouldBeEqualToItself() {
            assertThat(user).isEqualTo(user);
        }

        @Test
        @DisplayName("should not be equal to null")
        void shouldNotBeEqualToNull() {
            assertThat(user).isNotEqualTo(null);
        }

        @Test
        @DisplayName("should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            assertThat(user).isNotEqualTo("not a user");
        }

        @Test
        @DisplayName("users without id should not be equal")
        void usersWithoutIdShouldNotBeEqual() {
            User user1 = User.builder().email("test@example.com").build();
            User user2 = User.builder().email("test@example.com").build();

            // Both have null IDs, so equals returns false per implementation
            assertThat(user1).isNotEqualTo(user2);
        }

        @Test
        @DisplayName("hashCode should be consistent")
        void hashCodeShouldBeConsistent() {
            int hashCode1 = user.hashCode();
            int hashCode2 = user.hashCode();

            assertThat(hashCode1).isEqualTo(hashCode2);
        }
    }

    @Nested
    @DisplayName("toString")
    class ToString {

        @Test
        @DisplayName("should return string representation with id and email")
        void shouldReturnStringRepresentation() {
            String result = user.toString();

            assertThat(result).contains("User");
            assertThat(result).contains("email='john.doe@example.com'");
        }
    }
}
