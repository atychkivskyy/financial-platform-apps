package com.atychkivskyy.authservice.e2e;

import com.atychkivskyy.authservice.entity.Role;
import com.atychkivskyy.authservice.repository.RoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Profile("test")
public class TestDataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(TestDataInitializer.class);

    private final RoleRepository roleRepository;

    public TestDataInitializer(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) throws Exception {
        log.info("Initializing test data...");

        createRoleIfNotExists("ROLE_USER", "Standard user");
        createRoleIfNotExists("ROLE_ADMIN", "Administrator");

        log.info("Test data initialization complete. Roles count: {}", roleRepository.count());
    }

    private void createRoleIfNotExists(String name, String description) {
        if (roleRepository.findByName(name).isEmpty()) {
            Role role = new Role(name);
            role.setDescription(description);
            roleRepository.save(role);
            log.info("Created role: {}", name);
        }
    }
}
