package com.atychkivskyy.authservice.service;

import com.atychkivskyy.authservice.config.JwtConfig;
import com.atychkivskyy.authservice.entity.RefreshToken;
import com.atychkivskyy.authservice.entity.User;
import com.atychkivskyy.authservice.exception.TokenExpiredException;
import com.atychkivskyy.authservice.exception.TokenNotFoundException;
import com.atychkivskyy.authservice.repository.RefreshTokenRepository;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
@EnableConfigurationProperties(JwtConfig.class)
public class RefreshTokenService {

    private static final int TOKEN_LENGTH = 32;
    private static final int MAX_ACTIVE_TOKENS_PER_USER = 5;

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtConfig jwtConfig;
    private final SecureRandom secureRandom;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, JwtConfig jwtConfig) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtConfig = jwtConfig;
        this.secureRandom = new SecureRandom();
    }

    @Transactional
    public RefreshToken createRefreshToken(User user) {
        long activeTokens = refreshTokenRepository.countActiveTokensByUserId(user.getId(), Instant.now());

        if (activeTokens >= MAX_ACTIVE_TOKENS_PER_USER) {
            refreshTokenRepository.revokeAllByUserId(user.getId(), Instant.now());
        }

        String token = generateSecureToken();
        Instant expiresAt = Instant.now().plusMillis(jwtConfig.refreshTokenExpiration());

        RefreshToken refreshToken = RefreshToken.create(user, token, expiresAt);
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional(readOnly = true)
    public RefreshToken validateRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
            .orElseThrow(() -> new TokenNotFoundException("Refresh token not found"));

        if (refreshToken.isRevoked()) {
            throw new TokenExpiredException("Refresh token has been revoked");
        }

        if (refreshToken.isExpired()) {
            throw new TokenExpiredException("Refresh token has expired");
        }

        return refreshToken;
    }

    @Transactional
    public void revokeRefreshToken(String token) {
        refreshTokenRepository.findByToken(token)
            .ifPresent(RefreshToken::revoke);
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllByUserId(user.getId(), Instant.now());
    }

    @Scheduled(cron = "0 0 2 * * ?")
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = refreshTokenRepository.deleteExpiredAndRevokedTokens(Instant.now());
    }

    private String generateSecureToken() {
        byte[] tokenBytes = new byte[TOKEN_LENGTH];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
