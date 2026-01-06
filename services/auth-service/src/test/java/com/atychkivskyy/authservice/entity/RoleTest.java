package com.atychkivskyy.authservice.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Role Entity")
class RoleTest {

    @Nested
    @DisplayName("Construction")
    class Construction {

        @Test
        @DisplayName("Should create role with default constructor")
        void shouldCreateRoleWithDefaultConstructor() {
            Role role = new Role();

            assertThat(role.getId()).isNull();
            assertThat(role.getName()).isNull();
            assertThat(role.getDescription()).isNull();
            assertThat(role.getCreatedAt()).isNull();
        }

        @Test
        @DisplayName("Should create role with name only")
        void shouldCreateRoleWithNameOnly() {
            String name = "ROLE_USER";

            Role role = new Role(name);

            assertThat(role.getName()).isEqualTo(name);
            assertThat(role.getDescription()).isNull();
        }

        @Test
        @DisplayName("Should create role with name and description")
        void shouldCreateRoleWithNameAndDescription() {
            String roleName = "ROLE_ADMIN";
            String description = "Administrator with full access";

            Role role = new Role(roleName, description);

            assertThat(role.getName()).isEqualTo(roleName);
            assertThat(role.getDescription()).isEqualTo(description);
        }
    }

    @Nested
    @DisplayName("Setters")
    class Setters {

        @Test
        @DisplayName("Should update name")
        void shouldUpdateName() {
            Role role = new Role("ROLE_USER");

            role.setName("ROLE_MODERATOR");

            assertThat(role.getName()).isEqualTo("ROLE_MODERATOR");
        }

        @Test
        @DisplayName("Should update description")
        void shouldUpdateDescription() {
            Role role = new Role("ROLE_USER");

            role.setDescription("Standard user role");

            assertThat(role.getDescription()).isEqualTo("Standard user role");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Contract")
    class EqualsAndHashCode {

        @Test
        @DisplayName("Should be equal when names are the same")
        void shouldBeEqualWhenNamesAreSame() {
            Role role1 = new Role("ROLE_USER");
            Role role2 = new Role("ROLE_USER");

            assertThat(role1).isEqualTo(role2);
            assertThat(role1.hashCode()).isEqualTo(role2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when names are different")
        void shouldNotBeEqualWhenNamesAreDifferent() {
            Role role1 = new Role("ROLE_USER");
            Role role2 = new Role("ROLE_ADMIN");

            assertThat(role1).isNotEqualTo(role2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            Role role = new Role("ROLE_USER");

            assertThat(role).isEqualTo(role);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            Role role = new Role("ROLE_USER");

            assertThat(role).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            Role role = new Role("ROLE_USER");

            assertThat(role).isNotEqualTo("ROLE_USER");
        }

        @Test
        @DisplayName("Should be equal regardless of description")
        void shouldBeEqualRegardlessOfDescription() {
            Role role1 = new Role("ROLE_USER", "Description 1");
            Role role2 = new Role("ROLE_USER", "Description 2");

            assertThat(role1).isEqualTo(role2);
            assertThat(role1.hashCode()).isEqualTo(role2.hashCode());
        }

        @Test
        @DisplayName("Should handle null name in equality check")
        void shouldHandleNullNameInEqualityCheck() {
            Role role1 = new Role();
            Role role2 = new Role();

            assertThat(role1).isEqualTo(role2);
            assertThat(role1.hashCode()).isEqualTo(role2.hashCode());
        }
    }

    @Nested
    @DisplayName("toString")
    class ToString {

        @Test
        @DisplayName("Should return name as string representation")
        void shouldReturnNameAsStringRepresentation() {
            Role role = new Role("ROLE_ADMIN");

            assertThat(role.toString()).isEqualTo("ROLE_ADMIN");
        }

        @Test
        @DisplayName("Should return null when name is not set")
        void shouldReturnNullWhenNameIsNotSet() {
            Role role = new Role();

            assertThat(role.toString()).isNull();
        }
    }

    @Nested
    @DisplayName("Lifecycle Callbacks")
    class LifecycleCallbacks {

        @Test
        @DisplayName("onCreate should set createdAt timestamp")
        void onCreateShouldSetCreatedAtTimestamp() {
            Role role = new Role("ROLE_USER");
            assertThat(role.getCreatedAt()).isNull();

            role.onCreate();

            assertThat(role.getCreatedAt()).isNotNull();
        }
    }
}
