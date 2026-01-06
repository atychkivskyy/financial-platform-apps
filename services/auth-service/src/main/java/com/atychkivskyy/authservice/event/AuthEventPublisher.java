package com.atychkivskyy.authservice.event;

import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Component
public class AuthEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(AuthEventPublisher.class);

    private static final String USER_REGISTERED_TOPIC = "auth.user.registered";
    private static final String USER_LOGIN_TOPIC = "auth.user.login";

    private final KafkaTemplate<String, Object> kafkaTemplate;

    public AuthEventPublisher(KafkaTemplate<String, Object> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void publishUserRegistered(User user) {
        UserRegisteredEvent event = UserRegisteredEvent.create(
            user.getId(),
            user.getEmail(),
            user.getFirstName(),
            user.getLastName(),
            user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet())
        );

        publishEvent(USER_REGISTERED_TOPIC, user.getId().toString(), event);
    }

    public void publishUserLoginSuccess(User user, String ipAddress, String userAgent) {
        UserLoginEvent event = UserLoginEvent.success(
            user.getId(),
            user.getEmail(),
            ipAddress,
            userAgent
        );

        publishEvent(USER_LOGIN_TOPIC, user.getId().toString(), event);
    }

    public void publishUserLoginFailure(String email, String ipAddress, String userAgent, String reason) {
        UserLoginEvent event = UserLoginEvent.failure(
            email,
            ipAddress,
            userAgent,
            reason
        );

        publishEvent(USER_LOGIN_TOPIC, email, event);
    }

    private void publishEvent(String topic, String key, Object event) {
        CompletableFuture<SendResult<String, Object>> future = kafkaTemplate.send(topic, key, event);

        future.whenComplete((result, ex) -> {
            if (ex != null) {
                log.error("Failed to publish event to topic {}: {}", topic, ex.getMessage(), ex);
            } else {
                log.debug("Event published to topic {} with offset {}", topic, result.getRecordMetadata().offset());
            }
        });
    }
}
