package com.example.auth.service;

import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.repository.PermissionRepository;
import com.example.auth.repository.RoleRepository;
import com.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Service for managing user operations including creation, authentication, and role management.
 */
@Service
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, 
                      RoleRepository roleRepository,
                      PermissionRepository permissionRepository,
                      PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Find user by username (case-insensitive).
     * @param username the username to search for
     * @return Optional containing the user if found
     */
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /**
     * Find user by ID.
     * @param id the user ID
     * @return Optional containing the user if found
     */
    @Transactional(readOnly = true)
    public Optional<User> findById(UUID id) {
        return userRepository.findById(id);
    }

    /**
     * Save user entity.
     * @param user the user to save
     * @return saved user entity
     */
    public User save(User user) {
        return userRepository.save(user);
    }

    /**
     * Create a new user with encoded password.
     * @param username the username
     * @param plainPassword the plain text password
     * @param roles set of role names to assign
     * @return created user
     */
    public User createUser(String username, String plainPassword, Set<String> roleNames) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        String encodedPassword = passwordEncoder.encode(plainPassword);
        User user = new User(username, encodedPassword);
        
        // Assign roles
        if (roleNames != null && !roleNames.isEmpty()) {
            Set<Role> roles = roleRepository.findByNameIn(roleNames);
            user.setRoles(roles);
        }

        User savedUser = userRepository.save(user);
        logger.info("Created new user: {}", username);
        return savedUser;
    }

    /**
     * Verify user password.
     * @param user the user entity
     * @param plainPassword the plain text password to verify
     * @return true if password matches
     */
    public boolean verifyPassword(User user, String plainPassword) {
        return passwordEncoder.matches(plainPassword, user.getPasswordHash());
    }

    /**
     * Update user password.
     * @param user the user entity
     * @param newPlainPassword the new plain text password
     * @return updated user
     */
    public User updatePassword(User user, String newPlainPassword) {
        String encodedPassword = passwordEncoder.encode(newPlainPassword);
        user.setPasswordHash(encodedPassword);
        User updatedUser = userRepository.save(user);
        logger.info("Password updated for user: {}", user.getUsername());
        return updatedUser;
    }

    /**
     * Enable or disable user account.
     * @param user the user entity
     * @param enabled true to enable, false to disable
     * @return updated user
     */
    public User setUserEnabled(User user, boolean enabled) {
        user.setEnabled(enabled);
        User updatedUser = userRepository.save(user);
        logger.info("User {} {}: {}", enabled ? "enabled" : "disabled", user.getUsername());
        return updatedUser;
    }

    /**
     * Add role to user.
     * @param user the user entity
     * @param roleName the role name to add
     * @return updated user
     */
    public User addRoleToUser(User user, String roleName) {
        Optional<Role> roleOpt = roleRepository.findByName(roleName);
        if (roleOpt.isEmpty()) {
            throw new IllegalArgumentException("Role not found: " + roleName);
        }
        
        user.addRole(roleOpt.get());
        User updatedUser = userRepository.save(user);
        logger.info("Added role '{}' to user: {}", roleName, user.getUsername());
        return updatedUser;
    }

    /**
     * Remove role from user.
     * @param user the user entity
     * @param roleName the role name to remove
     * @return updated user
     */
    public User removeRoleFromUser(User user, String roleName) {
        Optional<Role> roleOpt = roleRepository.findByName(roleName);
        if (roleOpt.isEmpty()) {
            throw new IllegalArgumentException("Role not found: " + roleName);
        }
        
        user.removeRole(roleOpt.get());
        User updatedUser = userRepository.save(user);
        logger.info("Removed role '{}' from user: {}", roleName, user.getUsername());
        return updatedUser;
    }

    /**
     * Create default admin user if no users exist.
     * This method should be called during application startup.
     */
    @Transactional
    public void createDefaultAdmin() {
        // Check if any users exist
        if (userRepository.countUsers() > 0) {
            logger.debug("Users already exist, skipping default admin creation");
            return;
        }

        logger.info("No users found, creating default admin user");

        // Create default permissions
        Permission readPermission = createPermissionIfNotExists("system:read");
        Permission writePermission = createPermissionIfNotExists("system:write");
        Permission adminPermission = createPermissionIfNotExists("system:admin");
        Permission userManagementPermission = createPermissionIfNotExists("user:manage");

        // Create admin role with all permissions
        Role adminRole = createRoleIfNotExists("ROLE_ADMIN");
        adminRole.addPermission(readPermission);
        adminRole.addPermission(writePermission);
        adminRole.addPermission(adminPermission);
        adminRole.addPermission(userManagementPermission);
        roleRepository.save(adminRole);

        // Create user role with basic permissions
        Role userRole = createRoleIfNotExists("ROLE_USER");
        userRole.addPermission(readPermission);
        roleRepository.save(userRole);

        // Create default admin user with password "123456" (as specified in requirements)
        String adminPassword = "123456";
        String encodedPassword = passwordEncoder.encode(adminPassword);
        
        User adminUser = new User("admin", encodedPassword);
        adminUser.addRole(adminRole);
        adminUser.addRole(userRole); // Admin also has user role
        
        userRepository.save(adminUser);
        
        logger.warn("Default admin user created with username 'admin' and password '123456'");
        logger.warn("IMPORTANT: Change the default admin password immediately in production!");
    }

    /**
     * Create permission if it doesn't exist.
     */
    private Permission createPermissionIfNotExists(String permissionName) {
        return permissionRepository.findByName(permissionName)
                .orElseGet(() -> {
                    Permission permission = new Permission(permissionName);
                    return permissionRepository.save(permission);
                });
    }

    /**
     * Create role if it doesn't exist.
     */
    private Role createRoleIfNotExists(String roleName) {
        return roleRepository.findByName(roleName)
                .orElseGet(() -> {
                    Role role = new Role(roleName);
                    return roleRepository.save(role);
                });
    }

    /**
     * Get total number of users.
     * @return user count
     */
    @Transactional(readOnly = true)
    public long getUserCount() {
        return userRepository.countUsers();
    }

    /**
     * Check if username exists.
     * @param username the username to check
     * @return true if username exists
     */
    @Transactional(readOnly = true)
    public boolean usernameExists(String username) {
        return userRepository.existsByUsername(username);
    }
}