package com.atychkivskyy.authservice.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "jwt")
@Validated
public record JwtConfig(
    @NotBlank(message = "JWT secret is required")
    String secret,

    @Positive(message = "Access token expiration must be positive")
    long accessTokenExpiration,

    @Positive(message = "Refresh token expiration must be positive")
    long refreshTokenExpiration,

    @NotBlank(message = "JWT issuer is required")
    String issuer
) {
    public JwtConfig {
        if (issuer == null || issuer.isBlank()) {
            issuer = "finplatform-auth-service";
        }
    }
}
