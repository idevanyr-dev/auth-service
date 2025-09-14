package com.example.auth.util;

/**
 * Utility class for Redis key patterns used throughout the application.
 * Centralizes key naming conventions for consistency and maintenance.
 */
public final class RedisKeys {

    private RedisKeys() {
        // Utility class - prevent instantiation
    }

    // Prefixes for different types of keys
    public static final String REFRESH_TOKEN_PREFIX = "refresh:";
    public static final String BLACKLIST_PREFIX = "blacklist:";
    public static final String USER_SESSION_PREFIX = "session:";
    public static final String RATE_LIMIT_PREFIX = "rate_limit:";
    public static final String FAILED_LOGIN_PREFIX = "failed_login:";

    /**
     * Generate Redis key for refresh token storage.
     * @param refreshToken the refresh token
     * @return formatted Redis key
     */
    public static String refreshToken(String refreshToken) {
        return REFRESH_TOKEN_PREFIX + refreshToken;
    }

    /**
     * Generate Redis key for JWT blacklist storage.
     * @param jti the JWT ID (jti claim)
     * @return formatted Redis key
     */
    public static String blacklistToken(String jti) {
        return BLACKLIST_PREFIX + jti;
    }

    /**
     * Generate Redis key for user session tracking.
     * @param userId the user ID
     * @param sessionId the session ID
     * @return formatted Redis key
     */
    public static String userSession(String userId, String sessionId) {
        return USER_SESSION_PREFIX + userId + ":" + sessionId;
    }

    /**
     * Generate Redis key for rate limiting by IP address.
     * @param ipAddress the client IP address
     * @return formatted Redis key
     */
    public static String rateLimitByIp(String ipAddress) {
        return RATE_LIMIT_PREFIX + "ip:" + ipAddress;
    }

    /**
     * Generate Redis key for rate limiting by user.
     * @param username the username
     * @return formatted Redis key
     */
    public static String rateLimitByUser(String username) {
        return RATE_LIMIT_PREFIX + "user:" + username;
    }

    /**
     * Generate Redis key for failed login attempt tracking.
     * @param identifier the identifier (IP or username)
     * @return formatted Redis key
     */
    public static String failedLoginAttempts(String identifier) {
        return FAILED_LOGIN_PREFIX + identifier;
    }

    /**
     * Generate Redis key for user's active refresh tokens (for revoke all functionality).
     * @param userId the user ID
     * @return formatted Redis key
     */
    public static String userRefreshTokens(String userId) {
        return "user_tokens:" + userId;
    }

    /**
     * Generate Redis key for storing user roles cache.
     * @param userId the user ID
     * @return formatted Redis key
     */
    public static String userRolesCache(String userId) {
        return "user_roles:" + userId;
    }

    /**
     * Generate Redis key for storing user permissions cache.
     * @param userId the user ID
     * @return formatted Redis key
     */
    public static String userPermissionsCache(String userId) {
        return "user_permissions:" + userId;
    }

    /**
     * Generate Redis key for application-wide settings cache.
     * @param settingKey the setting key
     * @return formatted Redis key
     */
    public static String appSetting(String settingKey) {
        return "app_setting:" + settingKey;
    }

    /**
     * Extract the original token/identifier from a Redis key.
     * @param redisKey the Redis key
     * @param prefix the expected prefix
     * @return the extracted identifier or null if prefix doesn't match
     */
    public static String extractIdentifier(String redisKey, String prefix) {
        if (redisKey != null && redisKey.startsWith(prefix)) {
            return redisKey.substring(prefix.length());
        }
        return null;
    }

    /**
     * Check if a Redis key has the expected prefix.
     * @param redisKey the Redis key
     * @param prefix the expected prefix
     * @return true if key has the prefix
     */
    public static boolean hasPrefix(String redisKey, String prefix) {
        return redisKey != null && redisKey.startsWith(prefix);
    }
}