package com.atychkivskyy.authservice.user.application;

import com.atychkivskyy.authservice.user.domain.Role;
import com.atychkivskyy.authservice.user.domain.User;
import com.atychkivskyy.authservice.user.persistence.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.UUID;

@Service
@Transactional
public class UserService {
    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;

    public UserService(UserRepository userRepository, PasswordHasher passwordHasher) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
    }

    public User registerUser(String email, String rawPassword, Set<Role> roles) {
        if (userRepository.existsByEmail(email.toLowerCase())) {
            throw new UserAlreadyExistsException(email);
        }

        String passwordHash = passwordHasher.hash(rawPassword);
        User user = User.create(email, passwordHash, roles);

        return userRepository.save(user);
    }

    public void disableUser(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        user.disable();
    }

    public void enableUser(UUID userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        user.enable();
    }
}
