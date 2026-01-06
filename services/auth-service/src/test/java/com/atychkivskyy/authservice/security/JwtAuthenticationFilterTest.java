package com.atychkivskyy.authservice.security;

import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;
import com.atychkivskyy.authservice.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtAuthenticationFilter")
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private FilterChain filterChain;

    private JwtAuthenticationFilter jwtAuthenticationFilter;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtService, userDetailsService);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("When Authorization header is missing")
    class MissingAuthorizationHeader {

        @Test
        @DisplayName("should continue filter chain without authentication")
        void shouldContinueFilterChainWithoutAuthentication() throws ServletException, IOException {
            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verifyNoInteractions(jwtService, userDetailsService);
        }
    }

    @Nested
    @DisplayName("When Authorization header has invalid format")
    class InvalidAuthorizationHeader {

        @Test
        @DisplayName("should continue filter chain when header doesn't start with Bearer")
        void shouldContinueWhenNotBearerToken() throws ServletException, IOException {
            request.addHeader("Authorization", "Basic sometoken");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verifyNoInteractions(jwtService, userDetailsService);
        }

        @Test
        @DisplayName("should continue filter chain when header is empty Bearer")
        void shouldContinueWhenEmptyBearer() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer ");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    @DisplayName("When valid JWT token is provided")
    class ValidJwtToken {

        private SecurityUserDetails userDetails;
        private static final String VALID_TOKEN = "valid.jwt.token";
        private static final String USER_EMAIL = "user@example.com";

        @BeforeEach
        void setUp() {
            User user = User.builder()
                .email(USER_EMAIL)
                .passwordHash("hashedPassword")
                .firstName("Test")
                .lastName("User")
                .enabled(true)
                .roles(Set.of(new Role("ROLE_USER")))
                .build();
            userDetails = new SecurityUserDetails(user);
        }

        @Test
        @DisplayName("should set authentication in SecurityContext when token is valid")
        void shouldSetAuthenticationWhenTokenIsValid() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);

            when(jwtService.extractUsername(VALID_TOKEN)).thenReturn(USER_EMAIL);
            when(userDetailsService.loadUserByUsername(USER_EMAIL)).thenReturn(userDetails);
            when(jwtService.isTokenValid(VALID_TOKEN, userDetails)).thenReturn(true);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNotNull();
            assertThat(authentication.isAuthenticated()).isTrue();
            assertThat(authentication.getPrincipal()).isEqualTo(userDetails);
            assertThat(authentication.getName()).isEqualTo(USER_EMAIL);
        }

        @Test
        @DisplayName("should include authorities from UserDetails")
        void shouldIncludeAuthoritiesFromUserDetails() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);

            when(jwtService.extractUsername(VALID_TOKEN)).thenReturn(USER_EMAIL);
            when(userDetailsService.loadUserByUsername(USER_EMAIL)).thenReturn(userDetails);
            when(jwtService.isTokenValid(VALID_TOKEN, userDetails)).thenReturn(true);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNotNull();
            assertThat(authentication.getAuthorities())
                .extracting("authority")
                .containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("should NOT set authentication when token is invalid")
        void shouldNotSetAuthenticationWhenTokenIsInvalid() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer " + VALID_TOKEN);

            when(jwtService.extractUsername(VALID_TOKEN)).thenReturn(USER_EMAIL);
            when(userDetailsService.loadUserByUsername(USER_EMAIL)).thenReturn(userDetails);
            when(jwtService.isTokenValid(VALID_TOKEN, userDetails)).thenReturn(false);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }
    }

    @Nested
    @DisplayName("When username cannot be extracted from token")
    class UsernameExtractionFailure {

        @Test
        @DisplayName("should continue filter chain when username is null")
        void shouldContinueWhenUsernameIsNull() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer invalid.token");

            when(jwtService.extractUsername("invalid.token")).thenReturn(null);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verifyNoInteractions(userDetailsService);
        }
    }

    @Nested
    @DisplayName("When JWT processing throws exception")
    class JwtProcessingException {

        @Test
        @DisplayName("should continue filter chain when exception occurs")
        void shouldContinueWhenExceptionOccurs() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer malformed.token");

            when(jwtService.extractUsername("malformed.token"))
                .thenThrow(new RuntimeException("Invalid token"));

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }

        @Test
        @DisplayName("should continue filter chain when user not found")
        void shouldContinueWhenUserNotFound() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer valid.token");

            when(jwtService.extractUsername("valid.token")).thenReturn("unknown@example.com");
            when(userDetailsService.loadUserByUsername("unknown@example.com"))
                .thenThrow(new RuntimeException("User not found"));

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        }
    }

    @Nested
    @DisplayName("When authentication already exists")
    class ExistingAuthentication {

        @Test
        @DisplayName("should not override existing authentication")
        void shouldNotOverrideExistingAuthentication() throws ServletException, IOException {
            request.addHeader("Authorization", "Bearer valid.token");

            // Pre-set authentication
            Authentication existingAuth = mock(Authentication.class);
            SecurityContextHolder.getContext().setAuthentication(existingAuth);

            when(jwtService.extractUsername("valid.token")).thenReturn("user@example.com");

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
            // Should not load user details since auth already exists
            verifyNoInteractions(userDetailsService);
            // Should keep existing authentication
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existingAuth);
        }
    }

    @Nested
    @DisplayName("Multiple roles handling")
    class MultipleRolesHandling {

        @Test
        @DisplayName("should set authentication with multiple roles")
        void shouldSetAuthenticationWithMultipleRoles() throws ServletException, IOException {
            User user = User.builder()
                .email("admin@example.com")
                .passwordHash("hashedPassword")
                .firstName("Admin")
                .lastName("User")
                .enabled(true)
                .roles(Set.of(
                    new Role("ROLE_USER"),
                    new Role("ROLE_ADMIN"),
                    new Role("ROLE_MODERATOR")
                ))
                .build();
            SecurityUserDetails adminDetails = new SecurityUserDetails(user);

            request.addHeader("Authorization", "Bearer admin.token");

            when(jwtService.extractUsername("admin.token")).thenReturn("admin@example.com");
            when(userDetailsService.loadUserByUsername("admin@example.com")).thenReturn(adminDetails);
            when(jwtService.isTokenValid("admin.token", adminDetails)).thenReturn(true);

            jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            assertThat(authentication).isNotNull();
            assertThat(authentication.getAuthorities())
                .extracting("authority")
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MODERATOR");
        }
    }
}
