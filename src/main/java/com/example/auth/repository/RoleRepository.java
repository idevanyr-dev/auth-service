package com.example.auth.repository;

import com.example.auth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Repository for Role entity operations.
 * Provides standard CRUD operations plus custom queries.
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    /**
     * Find role by name (case-insensitive).
     * @param name the role name to search for
     * @return Optional containing the role if found
     */
    @Query("SELECT r FROM Role r WHERE LOWER(r.name) = LOWER(:name)")
    Optional<Role> findByName(@Param("name") String name);

    /**
     * Check if a role exists with the given name.
     * @param name the role name to check
     * @return true if role exists, false otherwise
     */
    boolean existsByName(String name);

    /**
     * Find all roles that have specific permissions.
     * @param permissionNames set of permission names
     * @return set of roles that contain any of the specified permissions
     */
    @Query("SELECT DISTINCT r FROM Role r JOIN r.permissions p WHERE p.name IN :permissionNames")
    Set<Role> findRolesByPermissionNames(@Param("permissionNames") Set<String> permissionNames);

    /**
     * Find roles by names (useful for bulk operations).
     * @param names set of role names
     * @return set of roles with matching names
     */
    @Query("SELECT r FROM Role r WHERE r.name IN :names")
    Set<Role> findByNameIn(@Param("names") Set<String> names);
}