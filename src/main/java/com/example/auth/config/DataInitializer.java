package com.example.auth.config;

import com.example.auth.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Initializes default data (like admin user) after the application context is ready.
 * This avoids circular dependencies between security and services.
 */
@Component
public class DataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);
    private final UserService userService;

    public DataInitializer(UserService userService) {
        this.userService = userService;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            userService.createDefaultAdmin();
            log.info("Default admin ensured");
        } catch (Exception e) {
            log.warn("Failed to create default admin user: {}", e.getMessage());
        }
    }
}
