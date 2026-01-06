package com.atychkivskyy.authservice.repository;

import com.atychkivskyy.authservice.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Query("""
        UPDATE RefreshToken token
        SET token.revoked = true, token.revokedAt = :revokedAt
        WHERE token.user.id = :userId AND token.revoked = false
        """)
    void revokeAllByUserId(@Param("userId") UUID userId, @Param("revokedAt") Instant revokedAt);

    @Modifying
    @Query("""
        DELETE FROM RefreshToken token
        WHERE token.revoked = true OR token.expiresAt < :now
        """)
    int deleteExpiredAndRevokedTokens(@Param("now") Instant now);

    @Query("""
        SELECT COUNT(token) FROM RefreshToken token
        WHERE token.user.id = :userId AND token.revoked = false AND token.expiresAt > :now
        """)
    long countActiveTokensByUserId(@Param("userId") UUID userId, @Param("now") Instant now);
}
