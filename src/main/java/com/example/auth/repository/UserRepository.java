package com.example.auth.repository;

import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Repository for User entity operations.
 * Provides standard CRUD operations plus custom queries.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * Find user by username (case-insensitive).
     * @param username the username to search for
     * @return Optional containing the user if found
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.username) = LOWER(:username)")
    Optional<User> findByUsername(@Param("username") String username);

    /**
     * Check if a user exists with the given username.
     * @param username the username to check
     * @return true if user exists, false otherwise
     */
    boolean existsByUsername(String username);

    /**
     * Find all enabled users.
     * @return list of enabled users
     */
    @Query("SELECT u FROM User u WHERE u.enabled = true")
    java.util.List<User> findAllEnabledUsers();

    /**
     * Count total number of users.
     * @return total count of users
     */
    @Query("SELECT COUNT(u) FROM User u")
    long countUsers();
}