package com.atychkivskyy.authservice.user.application;

public interface PasswordHasher {
    String hash(String rawPassword);
}
