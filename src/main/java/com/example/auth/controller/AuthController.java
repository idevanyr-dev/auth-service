package com.example.auth.controller;

import com.example.auth.dto.*;
import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.example.auth.service.AuthService;
import com.example.auth.service.exception.InvalidCredentialsException;
import com.example.auth.service.exception.InvalidRefreshTokenException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * REST Controller for authentication operations.
 * Provides endpoints for login, refresh, logout, and user information.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Authenticate user and return JWT tokens.
     * @param loginRequest the login credentials
     * @param request the HTTP request to extract client IP
     * @return TokenResponse containing access and refresh tokens
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest loginRequest, 
                                             HttpServletRequest request) {
        try {
            String clientIp = getClientIpAddress(request);
            
            TokenResponse tokens = authService.login(
                loginRequest.getUsername(), 
                loginRequest.getPassword(), 
                clientIp
            );
            
            logger.info("Login successful for user: {}", loginRequest.getUsername());
            return ResponseEntity.ok(tokens);
            
        } catch (InvalidCredentialsException e) {
            logger.warn("Login failed for user: {} - {}", loginRequest.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(null);
        } catch (Exception e) {
            logger.error("Login error for user: {} - {}", loginRequest.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(null);
        }
    }

    /**
     * Refresh access token using refresh token.
     * Implements refresh token rotation for enhanced security.
     * @param refreshRequest the refresh token request
     * @return TokenResponse with new access and refresh tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest refreshRequest) {
        try {
            TokenResponse tokens = authService.refresh(refreshRequest.getRefreshToken());
            
            logger.debug("Token refresh successful");
            return ResponseEntity.ok(tokens);
            
        } catch (InvalidRefreshTokenException e) {
            logger.warn("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(null);
        } catch (Exception e) {
            logger.error("Token refresh error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(null);
        }
    }

    /**
     * Logout user by revoking refresh token and blacklisting access token.
     * @param refreshRequest the refresh token to revoke
     * @param request the HTTP request to extract access token
     * @return No content response
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest refreshRequest,
                                      HttpServletRequest request) {
        try {
            // Extract access token from Authorization header for blacklisting
            String accessToken = extractAccessTokenFromRequest(request);
            
            authService.logout(refreshRequest.getRefreshToken(), Optional.ofNullable(accessToken));
            
            logger.info("Logout successful");
            return ResponseEntity.noContent().build();
            
        } catch (Exception e) {
            logger.error("Logout error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Get current authenticated user information.
     * @param request the HTTP request to extract access token
     * @return UserResponse with user details, roles, and permissions
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(HttpServletRequest request) {
        try {
            // Extract access token from Authorization header
            String accessToken = extractAccessTokenFromRequest(request);
            if (accessToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
            }

            Optional<User> userOpt = authService.validateTokenAndGetUser(accessToken);
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
            }

            User user = userOpt.get();
            UserResponse userResponse = convertToUserResponse(user);
            
            logger.debug("User info retrieved for: {}", user.getUsername());
            return ResponseEntity.ok(userResponse);
            
        } catch (Exception e) {
            logger.error("Error getting current user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    /**
     * Health check endpoint for the authentication service.
     * @return Simple status message
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Authentication service is running");
    }

    /**
     * Extract client IP address from request.
     * Considers various headers that may contain the real IP in proxy scenarios.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Extract access token from Authorization header.
     */
    private String extractAccessTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        
        if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }

    /**
     * Convert User entity to UserResponse DTO.
     */
    private UserResponse convertToUserResponse(User user) {
        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
                
        Set<String> permissions = user.getAllPermissions().stream()
                .map(Permission::getName)
                .collect(Collectors.toSet());
                
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEnabled(),
                user.getCreatedAt(),
                roles,
                permissions
        );
    }

    /**
     * Global exception handler for authentication-related exceptions.
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentials(InvalidCredentialsException e) {
        ErrorResponse error = new ErrorResponse("INVALID_CREDENTIALS", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    /**
     * Global exception handler for refresh token exceptions.
     */
    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRefreshToken(InvalidRefreshTokenException e) {
        ErrorResponse error = new ErrorResponse("INVALID_REFRESH_TOKEN", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    /**
     * Global exception handler for validation errors.
     */
    @ExceptionHandler(org.springframework.web.bind.MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(
            org.springframework.web.bind.MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        
        ErrorResponse error = new ErrorResponse("VALIDATION_ERROR", message);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }

    /**
     * Generic exception handler.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception e) {
        logger.error("Unexpected error in AuthController", e);
        ErrorResponse error = new ErrorResponse("INTERNAL_ERROR", "An unexpected error occurred");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    /**
     * Error response DTO for consistent error formatting.
     */
    public static class ErrorResponse {
        private String code;
        private String message;
        private long timestamp;

        public ErrorResponse(String code, String message) {
            this.code = code;
            this.message = message;
            this.timestamp = System.currentTimeMillis();
        }

        // Getters and setters
        public String getCode() { return code; }
        public void setCode(String code) { this.code = code; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    }
}