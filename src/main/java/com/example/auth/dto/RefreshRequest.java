package com.example.auth.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO for refresh token request.
 */
public class RefreshRequest {

    @NotBlank(message = "Refresh token is required")
    private String refreshToken;

    // Constructors
    public RefreshRequest() {}

    public RefreshRequest(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    // Getters and Setters
    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    @Override
    public String toString() {
        return "RefreshRequest{" +
                "refreshToken='[PROTECTED]'" +
                '}';
    }
}