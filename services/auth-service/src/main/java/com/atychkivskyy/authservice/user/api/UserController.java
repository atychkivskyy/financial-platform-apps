package com.atychkivskyy.authservice.user.api;

import com.atychkivskyy.authservice.user.application.UserService;
import com.atychkivskyy.authservice.user.domain.Role;
import com.atychkivskyy.authservice.user.domain.User;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse register(@Valid @RequestBody RegisterUserRequest request) {
        Set<Role> roles = request.roles()
            .stream()
            .map(Role::valueOf)
            .collect(Collectors.toSet());

        User user = userService.registerUser(
            request.email(),
            request.password(),
            roles
        );

        return UserResponse.from(user);
    }

    @PostMapping("/{id}/disable")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void disable(@PathVariable UUID id) {
        userService.disableUser(id);
    }

    @PostMapping("/{id}/enable")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void enable(@PathVariable UUID id) {
        userService.enableUser(id);
    }
}
