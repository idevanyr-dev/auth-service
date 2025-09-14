package com.example.auth.service;

import com.example.auth.dto.TokenResponse;
import com.example.auth.entity.User;
import com.example.auth.service.exception.InvalidCredentialsException;
import com.example.auth.service.exception.InvalidRefreshTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Service for orchestrating authentication operations including login, refresh, and logout.
 * This service coordinates between UserService and TokenService.
 */
@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserService userService;
    private final TokenService tokenService;

    @Autowired
    public AuthService(UserService userService, TokenService tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    /**
     * Authenticate user and generate tokens.
     * @param username the username
     * @param password the plain text password
     * @param clientIp the client IP address (optional)
     * @return TokenResponse with access and refresh tokens
     * @throws InvalidCredentialsException if credentials are invalid
     */
    public TokenResponse login(String username, String password, String clientIp) {
        logger.debug("Login attempt for username: {}", username);

        // Find user by username
        Optional<User> userOpt = userService.findByUsername(username);
        if (userOpt.isEmpty()) {
            logger.warn("Login failed - user not found: {}", username);
            throw new InvalidCredentialsException("Invalid username or password");
        }

        User user = userOpt.get();

        // Check if user is enabled
        if (!user.getEnabled()) {
            logger.warn("Login failed - user disabled: {}", username);
            throw new InvalidCredentialsException("User account is disabled");
        }

        // Verify password
        if (!userService.verifyPassword(user, password)) {
            logger.warn("Login failed - invalid password for user: {}", username);
            throw new InvalidCredentialsException("Invalid username or password");
        }

        // Generate tokens
        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user, clientIp);

        logger.info("Login successful for user: {}", username);

        return new TokenResponse(accessToken, refreshToken, tokenService.getAccessTokenTtlSeconds());
    }

    /**
     * Refresh access token using refresh token.
     * Implements refresh token rotation for security.
     * @param refreshToken the refresh token
     * @return TokenResponse with new access and refresh tokens
     * @throws InvalidRefreshTokenException if refresh token is invalid
     */
    public TokenResponse refresh(String refreshToken) {
        logger.debug("Token refresh attempt");

        // Validate refresh token
        if (!tokenService.validateRefreshToken(refreshToken)) {
            logger.warn("Token refresh failed - invalid refresh token");
            throw new InvalidRefreshTokenException("Invalid or expired refresh token");
        }

        // Get refresh token data
        Optional<TokenService.RefreshTokenData> tokenDataOpt = tokenService.getRefreshTokenData(refreshToken);
        if (tokenDataOpt.isEmpty()) {
            logger.warn("Token refresh failed - refresh token data not found");
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }

        TokenService.RefreshTokenData tokenData = tokenDataOpt.get();
        UUID userId = tokenData.getUserId();

        // Find user by ID
        Optional<User> userOpt = userService.findById(userId);
        if (userOpt.isEmpty()) {
            logger.warn("Token refresh failed - user not found: {}", userId);
            throw new InvalidRefreshTokenException("User account not found");
        }

        User user = userOpt.get();
        
        if (!user.getEnabled()) {
            logger.warn("Token refresh failed - user disabled: {}", userId);
            throw new InvalidRefreshTokenException("User account is disabled");
        }

        // Rotate refresh token (atomic operation)
        TokenResponse newTokens = tokenService.rotateRefreshToken(refreshToken, user);

        logger.info("Token refresh successful for user: {}", user.getUsername());

        return newTokens;
    }

    /**
     * Logout user by revoking refresh token and optionally blacklisting access token.
     * @param refreshToken the refresh token to revoke
     * @param accessToken the access token to blacklist (optional)
     */
    public void logout(String refreshToken, Optional<String> accessToken) {
        logger.debug("Logout attempt");

        // Revoke refresh token
        if (refreshToken != null && !refreshToken.trim().isEmpty()) {
            tokenService.revokeRefreshToken(refreshToken);
            logger.debug("Refresh token revoked");
        }

        // Blacklist access token if provided
        if (accessToken.isPresent() && !accessToken.get().trim().isEmpty()) {
            tokenService.blacklistAccessToken(accessToken.get());
            logger.debug("Access token blacklisted");
        }

        logger.info("Logout completed");
    }

    /**
     * Logout using only refresh token.
     * @param refreshToken the refresh token to revoke
     */
    public void logout(String refreshToken) {
        logout(refreshToken, Optional.empty());
    }

    /**
     * Validate access token and get user information.
     * @param accessToken the access token
     * @return Optional containing user if token is valid
     */
    @Transactional(readOnly = true)
    public Optional<User> validateTokenAndGetUser(String accessToken) {
        if (!tokenService.validateAccessToken(accessToken)) {
            return Optional.empty();
        }

        Optional<UUID> userIdOpt = tokenService.parseUserIdFromAccessToken(accessToken);
        if (userIdOpt.isEmpty()) {
            return Optional.empty();
        }

        Optional<User> userOpt = userService.findById(userIdOpt.get());
        if (userOpt.isEmpty()) {
            return Optional.empty();
        }

        User user = userOpt.get();
        if (!user.getEnabled()) {
            return Optional.empty();
        }

        return Optional.of(user);
    }

    /**
     * Revoke all refresh tokens for a user (useful for security incidents).
     * @param userId the user ID
     */
    public void revokeAllUserTokens(UUID userId) {
        logger.info("Revoking all tokens for user: {}", userId);
        Set<String> keys = tokenService.getAllRefreshTokenKeys();
        for (String key : keys) {
            Optional<TokenService.RefreshTokenData> tokenDataOpt = tokenService.getRefreshTokenDataByKey(key);
            if (tokenDataOpt.isPresent() && userId.equals(tokenDataOpt.get().getUserId())) {
                tokenService.deleteRefreshTokenByKey(key);
                logger.debug("Revoked refresh token: {} for user: {}", key, userId);
            }
        }
        logger.info("All refresh tokens revoked for user: {}", userId);
    }

    /**
     * Change password and revoke all existing tokens.
     * @param user the user
     * @param newPassword the new password
     */
    public void changePasswordAndRevokeTokens(User user, String newPassword) {
        // Update password
        userService.updatePassword(user, newPassword);
        
        // Revoke all tokens for this user
        revokeAllUserTokens(user.getId());
        
        logger.info("Password changed and all tokens revoked for user: {}", user.getUsername());
    }
}