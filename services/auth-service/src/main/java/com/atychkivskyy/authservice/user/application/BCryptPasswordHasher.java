package com.atychkivskyy.authservice.user.application;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Objects;

public class BCryptPasswordHasher implements PasswordHasher {

    private final PasswordEncoder passwordEncoder;

    public BCryptPasswordHasher(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public String hash(String rawPassword) {
        Objects.requireNonNull(rawPassword, "rawPassword must not be null");
        return passwordEncoder.encode(rawPassword);
    }
}
