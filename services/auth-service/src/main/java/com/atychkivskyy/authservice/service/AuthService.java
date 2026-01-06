package com.atychkivskyy.authservice.service;

import com.atychkivskyy.authservice.dto.request.LoginRequest;
import com.atychkivskyy.authservice.dto.request.RegisterRequest;
import com.atychkivskyy.authservice.dto.response.AuthResponse;
import com.atychkivskyy.authservice.dto.response.UserResponse;
import com.atychkivskyy.authservice.entity.RefreshToken;
import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;
import com.atychkivskyy.authservice.event.AuthEventPublisher;
import com.atychkivskyy.authservice.exception.AccountLockedException;
import com.atychkivskyy.authservice.exception.InvalidCredentialsException;
import com.atychkivskyy.authservice.exception.UserAlreadyExistsException;
import com.atychkivskyy.authservice.repository.RoleRepository;
import com.atychkivskyy.authservice.repository.UserRepository;
import com.atychkivskyy.authservice.security.SecurityUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration LOCK_DURATION = Duration.ofMinutes(30);
    private static final String DEFAULT_ROLE_NAME = "ROLE_USER";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthEventPublisher eventPublisher;
    private final TransactionTemplate transactionTemplate;

    public AuthService(
        UserRepository userRepository,
        RoleRepository roleRepository,
        PasswordEncoder passwordEncoder,
        JwtService jwtService,
        RefreshTokenService refreshTokenService,
        AuthEventPublisher eventPublisher,
        TransactionTemplate transactionTemplate
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.eventPublisher = eventPublisher;
        this.transactionTemplate = transactionTemplate;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        String email = normalizeEmail(request.email());
        log.info("Register request: {}", request.email());

        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("Email already registered: " + email);
        }

        Role userRole = roleRepository.findByName(DEFAULT_ROLE_NAME)
            .orElseThrow(() -> new IllegalStateException("Default role not found: " + DEFAULT_ROLE_NAME));

        User user = User.builder()
            .email(email)
            .passwordHash(passwordEncoder.encode(request.password()))
            .firstName(request.firstName().trim())
            .lastName(request.lastName().trim())
            .roles(Set.of(userRole))
            .enabled(true)
            .build();

        user = userRepository.save(user);
        log.info("Register successful: {}", user.getEmail());

        eventPublisher.publishUserRegistered(user);

        return createAuthResponse(user);
    }

    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {
        String email = normalizeEmail(request.email());
        log.debug("Login request: {}", email);

        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            eventPublisher.publishUserLoginFailure(email, ipAddress, userAgent, "User not found");
            throw new InvalidCredentialsException("Invalid email or password");
        }

        if (!user.isAccountNonLocked()) {
            if (isLockExpired(user)) {
                unlockUser(user);
            } else {
                eventPublisher.publishUserLoginFailure(email, ipAddress, userAgent, "Account locked");
                throw new AccountLockedException("Account is locked. Try again later.");
            }
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            handleFailedLogin(user);
            eventPublisher.publishUserLoginFailure(email, ipAddress, userAgent, "Invalid password");
            throw new InvalidCredentialsException("Invalid email or password");
        }

        if (user.getFailedLoginAttempts() > 0) {
            resetFailedAttempts(user);
        }

        log.info("Login successful: {}", user.getId());
        eventPublisher.publishUserLoginSuccess(user, ipAddress, userAgent);

        return transactionTemplate.execute(status -> createAuthResponse(user));
    }

    @Transactional
    public AuthResponse refreshAccessToken(String refreshToken) {
        RefreshToken token = refreshTokenService.validateRefreshToken(refreshToken);
        User user = token.getUser();

        refreshTokenService.revokeRefreshToken(refreshToken);

        return createAuthResponse(user);
    }

    @Transactional
    public void logout(String refreshToken) {
        refreshTokenService.revokeRefreshToken(refreshToken);
        log.debug("Logout successful: {}", refreshToken);
    }

    @Transactional
    public void logoutAllDevices(UUID userId) {
        User user  = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userId));

        refreshTokenService.revokeAllUserTokens(user);
        log.info("All sessions revoked for user: {}", user.getEmail());
    }

    @Transactional(readOnly = true)
    public UserResponse getCurrentUser(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userId));

        return UserResponse.from(user);
    }

    private AuthResponse createAuthResponse(User user) {
        SecurityUserDetails userDetails = new SecurityUserDetails(user);
        String accessToken = jwtService.generateAccessToken(userDetails);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return AuthResponse.of(
            accessToken,
            refreshToken.getToken(),
            jwtService.getAccessTokenExpiration(),
            UserResponse.from(user)
        );
    }

    private void handleFailedLogin(User user) {
        transactionTemplate.executeWithoutResult(status -> {
            User freshUser = userRepository.findById(user.getId()).orElseThrow();
            freshUser.incrementFailedLoginAttempts();

            if (freshUser.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                freshUser.lock();
                log.warn("Account locked after {} failed attempts: {}",
                    MAX_FAILED_ATTEMPTS, freshUser.getEmail());
            }

            userRepository.save(freshUser);
        });

    }

    private void resetFailedAttempts(User user) {
        transactionTemplate.executeWithoutResult(status -> {
            User freshUser = userRepository.findById(user.getId()).orElseThrow();
            freshUser.unlock();
            userRepository.save(freshUser);
        });
    }

    private void unlockUser(User user) {
        transactionTemplate.executeWithoutResult(status -> {
            User freshUser = userRepository.findById(user.getId()).orElseThrow();
            freshUser.unlock();
            userRepository.save(freshUser);
            log.info("Account unlocked: {}", freshUser.getEmail());
        });
    }

    private boolean isLockExpired(User user) {
        return user.getLockTime() == null || Instant.now().isAfter(user.getLockTime().plus(LOCK_DURATION));
    }

    private String normalizeEmail(String email) {
        return email.toLowerCase().trim();
    }

}
