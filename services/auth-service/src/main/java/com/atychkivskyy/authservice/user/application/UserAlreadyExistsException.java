package com.atychkivskyy.authservice.user.application;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String email) {
        super("User with email already exists: " + email);
    }
}
