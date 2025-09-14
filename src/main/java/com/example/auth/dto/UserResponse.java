package com.example.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;
import java.util.Set;
import java.util.UUID;

/**
 * DTO for user response containing user information and roles.
 */
public class UserResponse {

    private UUID id;

    private String username;

    private boolean enabled;

    @JsonProperty("created_at")
    private OffsetDateTime createdAt;

    private Set<String> roles;

    private Set<String> permissions;

    // Constructors
    public UserResponse() {}

    public UserResponse(UUID id, String username, boolean enabled, OffsetDateTime createdAt, 
                       Set<String> roles, Set<String> permissions) {
        this.id = id;
        this.username = username;
        this.enabled = enabled;
        this.createdAt = createdAt;
        this.roles = roles;
        this.permissions = permissions;
    }

    // Getters and Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions;
    }

    @Override
    public String toString() {
        return "UserResponse{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", enabled=" + enabled +
                ", createdAt=" + createdAt +
                ", roles=" + roles +
                ", permissions=" + permissions +
                '}';
    }
}