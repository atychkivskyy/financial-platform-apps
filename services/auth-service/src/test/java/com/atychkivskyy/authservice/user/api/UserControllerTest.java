package com.atychkivskyy.authservice.user.api;

import com.atychkivskyy.authservice.user.application.UserAlreadyExistsException;
import com.atychkivskyy.authservice.user.application.UserService;
import com.atychkivskyy.authservice.user.domain.Role;
import com.atychkivskyy.authservice.user.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(UserApiExceptionHandler.class)
@ActiveProfiles("test")
public class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void shouldRegisterUser() throws Exception {
        User user = User.create(
            "user@example.com",
            "hashed-password",
            Set.of(Role.USER)
        );

        when(userService.registerUser(any(), any(), any()))
            .thenReturn(user);

        RegisterUserRequest request = new RegisterUserRequest(
            "user@example.com",
            "secret",
            Set.of("USER")
        );

        mockMvc.perform(
                post("/api/users")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request))
            )
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.email").value("user@example.com"))
            .andExpect(jsonPath("$.roles[0]").value("USER"))
            .andExpect(jsonPath("$.enabled").value(true));
    }

    @Test
    void shouldReturn409WhenUserAlreadyExists() throws Exception {
        when(userService.registerUser(any(), any(), any()))
            .thenThrow(new UserAlreadyExistsException("user@example.com"));

        RegisterUserRequest request = new RegisterUserRequest(
            "user@example.com",
            "secret",
            Set.of("USER")
        );

        mockMvc.perform(
                post("/api/users")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request))
            )
            .andExpect(status().isConflict());
    }

    @Test
    void shouldReturn400OnValidationError() throws Exception {
        RegisterUserRequest request = new RegisterUserRequest(
            "invalid-email",
            "",
            Set.of()
        );

        mockMvc.perform(
                post("/api/users")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(request))
            )
            .andExpect(status().isBadRequest());
    }

    @Test
    void shouldDisableUser() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(
                post("/api/users/{id}/disable", id)
            )
            .andExpect(status().isNoContent());
    }

    @Test
    void shouldEnableUser() throws Exception {
        UUID id = UUID.randomUUID();

        mockMvc.perform(
                post("/api/users/{id}/enable", id)
            )
            .andExpect(status().isNoContent());
    }
}
