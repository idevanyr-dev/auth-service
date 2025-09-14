package com.example.auth.repository;

import com.example.auth.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Repository for Permission entity operations.
 * Provides standard CRUD operations plus custom queries.
 */
@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    /**
     * Find permission by name (case-insensitive).
     * @param name the permission name to search for
     * @return Optional containing the permission if found
     */
    @Query("SELECT p FROM Permission p WHERE LOWER(p.name) = LOWER(:name)")
    Optional<Permission> findByName(@Param("name") String name);

    /**
     * Check if a permission exists with the given name.
     * @param name the permission name to check
     * @return true if permission exists, false otherwise
     */
    boolean existsByName(String name);

    /**
     * Find permissions by names (useful for bulk operations).
     * @param names set of permission names
     * @return set of permissions with matching names
     */
    @Query("SELECT p FROM Permission p WHERE p.name IN :names")
    Set<Permission> findByNameIn(@Param("names") Set<String> names);

    /**
     * Find all permissions for a specific user (through roles).
     * @param userId the user ID
     * @return set of permissions assigned to the user
     */
    @Query("SELECT DISTINCT p FROM Permission p " +
           "JOIN p.roles r " +
           "JOIN r.users u " +
           "WHERE u.id = :userId")
    Set<Permission> findPermissionsByUserId(@Param("userId") UUID userId);

    /**
     * Find permissions that start with a specific prefix (e.g., "product:").
     * @param prefix the permission name prefix
     * @return set of permissions with names starting with the prefix
     */
    @Query("SELECT p FROM Permission p WHERE p.name LIKE CONCAT(:prefix, '%')")
    Set<Permission> findByNameStartingWith(@Param("prefix") String prefix);
}