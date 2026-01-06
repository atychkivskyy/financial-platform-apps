package com.atychkivskyy.authservice.service;

import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;
import com.atychkivskyy.authservice.repository.UserRepository;
import com.atychkivskyy.authservice.security.SecurityUserDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("CustomUserDetailsService")
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User testUser;
    private Role userRole;
    private Role adminRole;

    @BeforeEach
    void setUp() {
        userRole = new Role("ROLE_USER");
        adminRole = new Role("ROLE_ADMIN");

        testUser = User.builder()
            .email("test@example.com")
            .passwordHash("$2a$10$hashedPassword")
            .firstName("Test")
            .lastName("User")
            .enabled(true)
            .roles(Set.of(userRole))
            .build();
    }

    @Nested
    @DisplayName("loadUserByUsername")
    class LoadUserByUsername {

        @Test
        @DisplayName("should return UserDetails when user exists")
        void shouldReturnUserDetailsWhenUserExists() {
            when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(testUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("test@example.com");

            assertThat(result).isNotNull();
            assertThat(result).isInstanceOf(SecurityUserDetails.class);
        }

        @Test
        @DisplayName("should return correct username from user email")
        void shouldReturnCorrectUsernameFromUserEmail() {
            when(userRepository.findByEmail("john.doe@example.com"))
                .thenReturn(Optional.of(User.builder()
                    .email("john.doe@example.com")
                    .passwordHash("hash")
                    .firstName("John")
                    .lastName("Doe")
                    .build()));

            UserDetails result = customUserDetailsService.loadUserByUsername("john.doe@example.com");

            assertThat(result.getUsername()).isEqualTo("john.doe@example.com");
        }

        @Test
        @DisplayName("should return correct password hash")
        void shouldReturnCorrectPasswordHash() {
            when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(testUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("test@example.com");

            assertThat(result.getPassword()).isEqualTo("$2a$10$hashedPassword");
        }

        @Test
        @DisplayName("should return correct authorities for single role")
        void shouldReturnCorrectAuthoritiesForSingleRole() {
            when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(testUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("test@example.com");

            assertThat(result.getAuthorities())
                .hasSize(1)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("should return correct authorities for multiple roles")
        void shouldReturnCorrectAuthoritiesForMultipleRoles() {
            User multiRoleUser = User.builder()
                .email("admin@example.com")
                .passwordHash("hash")
                .firstName("Admin")
                .lastName("User")
                .roles(Set.of(userRole, adminRole))
                .build();
            when(userRepository.findByEmail("admin@example.com"))
                .thenReturn(Optional.of(multiRoleUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("admin@example.com");

            assertThat(result.getAuthorities())
                .hasSize(2)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
        }

        @Test
        @DisplayName("should return enabled status correctly")
        void shouldReturnEnabledStatusCorrectly() {
            when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(testUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("test@example.com");

            assertThat(result.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("should return disabled status for disabled user")
        void shouldReturnDisabledStatusForDisabledUser() {
            User disabledUser = User.builder()
                .email("disabled@example.com")
                .passwordHash("hash")
                .firstName("Disabled")
                .lastName("User")
                .enabled(false)
                .build();
            when(userRepository.findByEmail("disabled@example.com"))
                .thenReturn(Optional.of(disabledUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("disabled@example.com");

            assertThat(result.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("should return account non locked status correctly")
        void shouldReturnAccountNonLockedStatusCorrectly() {
            when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(testUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("test@example.com");

            assertThat(result.isAccountNonLocked()).isTrue();
        }

        @Test
        @DisplayName("should return locked status for locked user")
        void shouldReturnLockedStatusForLockedUser() {
            User lockedUser = User.builder()
                .email("locked@example.com")
                .passwordHash("hash")
                .firstName("Locked")
                .lastName("User")
                .enabled(true)
                .build();
            lockedUser.lock();
            when(userRepository.findByEmail("locked@example.com"))
                .thenReturn(Optional.of(lockedUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("locked@example.com");

            assertThat(result.isAccountNonLocked()).isFalse();
        }

        @Test
        @DisplayName("should throw UsernameNotFoundException when user not found")
        void shouldThrowUsernameNotFoundExceptionWhenUserNotFound() {
            when(userRepository.findByEmail("nonexistent@example.com"))
                .thenReturn(Optional.empty());

            assertThatThrownBy(() ->
                customUserDetailsService.loadUserByUsername("nonexistent@example.com"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("User not found with email: nonexistent@example.com");
        }

        @Test
        @DisplayName("should include email in exception message when user not found")
        void shouldIncludeEmailInExceptionMessageWhenUserNotFound() {
            String searchEmail = "missing.user@company.org";
            when(userRepository.findByEmail(searchEmail))
                .thenReturn(Optional.empty());

            assertThatThrownBy(() ->
                customUserDetailsService.loadUserByUsername(searchEmail))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining(searchEmail);
        }

        @Test
        @DisplayName("should call repository with correct email")
        void shouldCallRepositoryWithCorrectEmail() {
            String email = "lookup@example.com";
            when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(User.builder()
                    .email(email)
                    .passwordHash("hash")
                    .firstName("Test")
                    .lastName("User")
                    .build()));

            customUserDetailsService.loadUserByUsername(email);

            verify(userRepository).findByEmail(email);
            verify(userRepository, times(1)).findByEmail(anyString());
        }

        @Test
        @DisplayName("should only call repository once")
        void shouldOnlyCallRepositoryOnce() {
            when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(testUser));

            customUserDetailsService.loadUserByUsername("test@example.com");

            verify(userRepository, times(1)).findByEmail("test@example.com");
            verifyNoMoreInteractions(userRepository);
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCases {

        @Test
        @DisplayName("should handle user with no roles")
        void shouldHandleUserWithNoRoles() {
            User noRolesUser = User.builder()
                .email("noroles@example.com")
                .passwordHash("hash")
                .firstName("No")
                .lastName("Roles")
                .roles(Set.of())
                .build();
            when(userRepository.findByEmail("noroles@example.com"))
                .thenReturn(Optional.of(noRolesUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("noroles@example.com");

            assertThat(result.getAuthorities()).isEmpty();
        }

        @Test
        @DisplayName("should handle email with special characters")
        void shouldHandleEmailWithSpecialCharacters() {
            String specialEmail = "user+tag@sub.example.com";
            User specialUser = User.builder()
                .email(specialEmail)
                .passwordHash("hash")
                .firstName("Special")
                .lastName("User")
                .build();
            when(userRepository.findByEmail(specialEmail))
                .thenReturn(Optional.of(specialUser));

            UserDetails result = customUserDetailsService.loadUserByUsername(specialEmail);

            assertThat(result.getUsername()).isEqualTo(specialEmail);
        }

        @Test
        @DisplayName("should handle case-sensitive email lookup")
        void shouldHandleCaseSensitiveEmailLookup() {
            // The service passes email as-is to repository
            // Case sensitivity depends on repository/database implementation
            String email = "Test@Example.com";
            when(userRepository.findByEmail(email))
                .thenReturn(Optional.empty());

            assertThatThrownBy(() ->
                customUserDetailsService.loadUserByUsername(email))
                .isInstanceOf(UsernameNotFoundException.class);

            verify(userRepository).findByEmail(email);
        }

        @Test
        @DisplayName("should return SecurityUserDetails with user ID")
        void shouldReturnSecurityUserDetailsWithUserId() {
            when(userRepository.findByEmail("test@example.com"))
                .thenReturn(Optional.of(testUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("test@example.com");

            assertThat(result).isInstanceOf(SecurityUserDetails.class);
            SecurityUserDetails securityUserDetails = (SecurityUserDetails) result;
            assertThat(securityUserDetails.getId()).isEqualTo(testUser.getId());
        }
    }

    @Nested
    @DisplayName("Integration Scenarios")
    class IntegrationScenarios {

        @Test
        @DisplayName("should support typical login flow - enabled user with roles")
        void shouldSupportTypicalLoginFlow() {
            User activeUser = User.builder()
                .email("active@example.com")
                .passwordHash("$2a$10$encodedPassword")
                .firstName("Active")
                .lastName("User")
                .enabled(true)
                .roles(Set.of(userRole))
                .build();
            when(userRepository.findByEmail("active@example.com"))
                .thenReturn(Optional.of(activeUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("active@example.com");

            // Verify all properties needed for authentication
            assertThat(result.getUsername()).isEqualTo("active@example.com");
            assertThat(result.getPassword()).isEqualTo("$2a$10$encodedPassword");
            assertThat(result.isEnabled()).isTrue();
            assertThat(result.isAccountNonLocked()).isTrue();
            assertThat(result.isAccountNonExpired()).isTrue();
            assertThat(result.isCredentialsNonExpired()).isTrue();
            assertThat(result.getAuthorities()).isNotEmpty();
        }

        @Test
        @DisplayName("should support admin user with multiple roles")
        void shouldSupportAdminUserWithMultipleRoles() {
            Role superAdminRole = new Role("ROLE_SUPER_ADMIN");
            User adminUser = User.builder()
                .email("superadmin@example.com")
                .passwordHash("hash")
                .firstName("Super")
                .lastName("Admin")
                .enabled(true)
                .roles(Set.of(userRole, adminRole, superAdminRole))
                .build();
            when(userRepository.findByEmail("superadmin@example.com"))
                .thenReturn(Optional.of(adminUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("superadmin@example.com");

            assertThat(result.getAuthorities())
                .hasSize(3)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_SUPER_ADMIN");
        }

        @Test
        @DisplayName("should handle suspended user scenario")
        void shouldHandleSuspendedUserScenario() {
            User suspendedUser = User.builder()
                .email("suspended@example.com")
                .passwordHash("hash")
                .firstName("Suspended")
                .lastName("User")
                .enabled(false)
                .roles(Set.of(userRole))
                .build();
            suspendedUser.lock();
            when(userRepository.findByEmail("suspended@example.com"))
                .thenReturn(Optional.of(suspendedUser));

            UserDetails result = customUserDetailsService.loadUserByUsername("suspended@example.com");

            assertThat(result.isEnabled()).isFalse();
            assertThat(result.isAccountNonLocked()).isFalse();
        }
    }
}
