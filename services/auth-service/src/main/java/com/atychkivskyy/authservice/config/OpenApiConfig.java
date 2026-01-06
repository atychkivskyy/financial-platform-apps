package com.atychkivskyy.authservice.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${spring.application.name}")
    private String applicationName;

    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "bearerAuth";

        return new OpenAPI()
            .info(new Info()
                .title("Finance Platform - Auth Service API")
                .version("1.0.0")
                .description("""
                    Authentication and authorization service for the Finance Platform.

                    ## Features
                    - User registration
                    - JWT-based authentication
                    - Token refresh
                    - Session management

                    ## Security
                    All endpoints except `/register`, `/login`, and `/refresh` require authentication.
                    Include the JWT token in the Authorization header: `Bearer <token>
                    """)
                .contact(new Contact()
                    .name("atychkivskyy")
                    .url("https://github.com/atychkivskyy"))
                .license(new License()
                    .name("MIT License")
                    .url("https://opensource.org/licenses/MIT")))
            .servers(List.of(
                new Server().url("http://localhost:8081").description("Local Development"),
                new Server().url("https://api.financial-platform-apps.com").description("Production")))
            .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
            .components(new Components()
                .addSecuritySchemes(securitySchemeName, new SecurityScheme()
                    .name(securitySchemeName)
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("JWT Authentication")));

    }
}
