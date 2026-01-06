package com.atychkivskyy.authservice.e2e;

import com.atychkivskyy.authservice.dto.request.LoginRequest;
import com.atychkivskyy.authservice.dto.request.RefreshTokenRequest;
import com.atychkivskyy.authservice.dto.request.RegisterRequest;

public final class TestData {

    public static final String VALID_EMAIL = "john.doe@example.com";
    public static final String VALID_PASSWORD = "SecurePass123!";
    public static final String VALID_FIRST_NAME = "John";
    public static final String VALID_LAST_NAME = "Doe";

    private TestData() {
    }

    public static RegisterRequest validRegisterRequest() {
        return new RegisterRequest(
            VALID_EMAIL,
            VALID_PASSWORD,
            VALID_FIRST_NAME,
            VALID_LAST_NAME
        );
    }

    public static RegisterRequest registerRequest(String email) {
        return new RegisterRequest(
            email,
            VALID_PASSWORD,
            VALID_FIRST_NAME,
            VALID_LAST_NAME
        );
    }

    public static RegisterRequest registerRequest(String email, String password) {
        return new RegisterRequest(
            email,
            password,
            VALID_FIRST_NAME,
            VALID_LAST_NAME
        );
    }

    public static RegisterRequest registerRequestWithName(String firstName, String lastName) {
        return new RegisterRequest(
            VALID_EMAIL,
            VALID_PASSWORD,
            firstName,
            lastName
        );
    }

    public static LoginRequest validLoginRequest() {
        return new LoginRequest(VALID_EMAIL, VALID_PASSWORD);
    }

    public static LoginRequest loginRequest(String email, String password) {
        return new LoginRequest(email, password);
    }

    public static RefreshTokenRequest refreshTokenRequest(String token) {
        return new RefreshTokenRequest(token);
    }

    public static class Invalid {
        public static final String INVALID_EMAIL = "not-an-email";
        public static final String INVALID_PASSWORD = "weak";
        public static final String BLANK = "";
        public static final String WHITESPACE = "      ";
    }
}
