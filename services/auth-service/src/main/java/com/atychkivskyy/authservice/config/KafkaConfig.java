package com.atychkivskyy.authservice.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaConfig {

    @Bean
    public NewTopic userRegisteredTopic() {
        return TopicBuilder.name("auth.user.registered")
            .partitions(3)
            .replicas(1)
            .build();
    }

    @Bean
    public NewTopic userLoginTopic() {
        return TopicBuilder.name("auth.user.login")
            .partitions(3)
            .replicas(1)
            .build();
    }
}
