package com.example.auth.service;

import com.example.auth.dto.TokenResponse;
import com.example.auth.entity.Permission;
import com.example.auth.entity.Role;
import com.example.auth.entity.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Service for handling JWT access tokens and opaque refresh tokens.
 * Implements RSA signing for JWT and Redis storage for refresh tokens.
 */
@Service
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);
    private static final String REFRESH_TOKEN_PREFIX = "refresh:";
    private static final String BLACKLIST_PREFIX = "blacklist:";

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;
    
    @Value("${security.jwt.private-key:}")
    private String privateKeyString;
    
    @Value("${security.jwt.public-key:}")
    private String publicKeyString;
    
    @Value("${security.jwt.private-key-file:}")
    private String privateKeyFile;
    
    @Value("${security.jwt.public-key-file:}")
    private String publicKeyFile;
    
    @Value("${security.jwt.access-token-ttl-seconds:600}")
    private long accessTokenTtlSeconds;
    
    @Value("${security.jwt.refresh-token-ttl-seconds:604800}")
    private long refreshTokenTtlSeconds;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public TokenService(RedisTemplate<String, String> redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    /**
     * Initialize RSA keys from configuration.
     * Called after dependency injection.
     */
    @jakarta.annotation.PostConstruct
    public void initKeys() {
        try {
            String effectivePrivate = resolveKey("private", privateKeyString, privateKeyFile);
            String effectivePublic = resolveKey("public", publicKeyString, publicKeyFile);

            if (effectivePrivate == null || effectivePrivate.isBlank()) {
                throw new IllegalStateException("JWT private key not configured. Provide JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_FILE.");
            }
            if (effectivePublic == null || effectivePublic.isBlank()) {
                throw new IllegalStateException("JWT public key not configured. Provide JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_FILE.");
            }

            this.privateKey = loadPrivateKey(effectivePrivate);
            this.publicKey = loadPublicKey(effectivePublic);
            
            logger.info("JWT keys initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize JWT keys", e);
            throw new RuntimeException("Failed to initialize JWT keys", e);
        }
    }

    /**
     * Resolve key content from direct string or file path. Preference order:
     * 1) Inline string property (Base64 PEM sem cabeçalho)
     * 2) File path property (conteúdo do arquivo será lido e limpo)
     */
    private String resolveKey(String kind, String inline, String filePath) {
        if (inline != null && !inline.isBlank()) {
            return inline;
        }
        if (filePath != null && !filePath.isBlank()) {
            try {
                java.nio.file.Path p = java.nio.file.Paths.get(filePath);
                if (!java.nio.file.Files.exists(p)) {
                    logger.error("JWT {} key file not found at {}", kind, filePath);
                    return null;
                }
                String content = java.nio.file.Files.readString(p);
                return content;
            } catch (Exception ex) {
                logger.error("Failed to read JWT {} key file {}: {}", kind, filePath, ex.getMessage());
                return null;
            }
        }
        return null;
    }

    /**
     * Generate JWT access token with RSA signing.
     * Contains user claims, roles, and permissions.
     */
    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiration = now.plus(accessTokenTtlSeconds, ChronoUnit.SECONDS);
        
        // Extract roles and permissions
        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
                
        Set<String> permissions = user.getAllPermissions().stream()
                .map(Permission::getName)
                .collect(Collectors.toSet());

        return Jwts.builder()
                .setSubject(user.getId().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiration))
                .setId(UUID.randomUUID().toString()) // jti for blacklist
                .claim("username", user.getUsername())
                .claim("roles", roles)
                .claim("permissions", permissions)
                .claim("enabled", user.getEnabled())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    /**
     * Generate opaque refresh token and store in Redis.
     */
    public String generateRefreshToken(User user) {
        return generateRefreshToken(user, null);
    }

    /**
     * Generate opaque refresh token with client IP and store in Redis.
     */
    public String generateRefreshToken(User user, String clientIp) {
        String refreshToken = UUID.randomUUID().toString();
        
        Instant now = Instant.now();
        Instant expiration = now.plus(refreshTokenTtlSeconds, ChronoUnit.SECONDS);
        
        RefreshTokenData tokenData = new RefreshTokenData(
                user.getId(),
                now.getEpochSecond(),
                expiration.getEpochSecond(),
                clientIp
        );
        
        try {
            String tokenDataJson = objectMapper.writeValueAsString(tokenData);
            String redisKey = REFRESH_TOKEN_PREFIX + refreshToken;
            
            redisTemplate.opsForValue().set(redisKey, tokenDataJson, refreshTokenTtlSeconds, TimeUnit.SECONDS);
            
            logger.debug("Refresh token generated for user: {}", user.getUsername());
            return refreshToken;
        } catch (JsonProcessingException e) {
            logger.error("Failed to serialize refresh token data", e);
            throw new RuntimeException("Failed to generate refresh token", e);
        }
    }

    /**
     * Validate JWT access token signature and expiration.
     */
    public boolean validateAccessToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
                    
            // Check if token is blacklisted
            String jti = claims.getBody().getId();
            if (jti != null && isTokenBlacklisted(jti)) {
                logger.warn("Access token is blacklisted: {}", jti);
                return false;
            }
            
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("Invalid access token: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Parse user ID from valid access token.
     */
    public Optional<UUID> parseUserIdFromAccessToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
                    
            String subject = claims.getBody().getSubject();
            return Optional.of(UUID.fromString(subject));
        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("Failed to parse user ID from token: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Parse claims from valid access token.
     */
    public Optional<Claims> parseClaimsFromAccessToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
                    
            return Optional.of(claims.getBody());
        } catch (JwtException | IllegalArgumentException e) {
            logger.debug("Failed to parse claims from token: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Validate refresh token by checking Redis existence.
     */
    public boolean validateRefreshToken(String token) {
        String redisKey = REFRESH_TOKEN_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(redisKey));
    }

    /**
     * Get refresh token data from Redis.
     */
    public Optional<RefreshTokenData> getRefreshTokenData(String token) {
        String redisKey = REFRESH_TOKEN_PREFIX + token;
        String tokenDataJson = redisTemplate.opsForValue().get(redisKey);
        
        if (tokenDataJson == null) {
            return Optional.empty();
        }
        
        try {
            RefreshTokenData tokenData = objectMapper.readValue(tokenDataJson, RefreshTokenData.class);
            return Optional.of(tokenData);
        } catch (JsonProcessingException e) {
            logger.error("Failed to deserialize refresh token data", e);
            return Optional.empty();
        }
    }

    /**
     * Revoke refresh token by removing from Redis.
     */
    public void revokeRefreshToken(String token) {
        String redisKey = REFRESH_TOKEN_PREFIX + token;
        redisTemplate.delete(redisKey);
        logger.debug("Refresh token revoked: {}", token);
    }

    /**
     * Rotate refresh token - generate new one and revoke old one atomically.
     */
    public TokenResponse rotateRefreshToken(String oldRefreshToken, User user) {
        // Validate old refresh token
        if (!validateRefreshToken(oldRefreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }
        
        // Get old token data for IP tracking
        Optional<RefreshTokenData> oldTokenData = getRefreshTokenData(oldRefreshToken);
        String clientIp = oldTokenData.map(RefreshTokenData::getClientIp).orElse(null);
        
        // Generate new tokens
        String newAccessToken = generateAccessToken(user);
        String newRefreshToken = generateRefreshToken(user, clientIp);
        
        // Revoke old refresh token
        revokeRefreshToken(oldRefreshToken);
        
        logger.debug("Refresh token rotated for user: {}", user.getUsername());
        
        return new TokenResponse(newAccessToken, newRefreshToken, accessTokenTtlSeconds);
    }

    /**
     * Add access token JTI to blacklist.
     */
    public void blacklistAccessToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
                    
            String jti = claims.getBody().getId();
            Date expiration = claims.getBody().getExpiration();
            
            if (jti != null && expiration != null) {
                long ttl = Math.max(0, expiration.getTime() - System.currentTimeMillis()) / 1000;
                
                if (ttl > 0) {
                    String blacklistKey = BLACKLIST_PREFIX + jti;
                    redisTemplate.opsForValue().set(blacklistKey, "true", ttl, TimeUnit.SECONDS);
                    logger.debug("Access token blacklisted: {}", jti);
                }
            }
        } catch (JwtException | IllegalArgumentException e) {
            logger.warn("Failed to blacklist invalid token: {}", e.getMessage());
        }
    }

    /**
     * Check if token JTI is blacklisted.
     */
    public boolean isTokenBlacklisted(String jti) {
        String blacklistKey = BLACKLIST_PREFIX + jti;
        return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
    }

    /**
     * Get access token TTL in seconds.
     * @return TTL in seconds
     */
    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    /**
     * Get refresh token TTL in seconds.
     * @return TTL in seconds
     */
    public long getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    /**
     * Load private key from PEM string (with or without Base64 encoding).
     */
    private PrivateKey loadPrivateKey(String keyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Case 1: Direct PEM content
        if (keyString.contains("BEGIN PRIVATE KEY")) {
            String pemBody = keyString
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(pemBody);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der));
        }

        // Case 2: Base64 decode first. It may be either DER bytes or PEM text.
        byte[] decoded = Base64.getDecoder().decode(keyString.replaceAll("\\s", ""));

        // If decoded starts with DER sequence (0x30), assume DER
        if (decoded.length > 0 && (decoded[0] & 0xFF) == 0x30) {
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decoded));
        }

        // Otherwise, try treating decoded as PEM text
        String maybePem = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        if (maybePem.contains("BEGIN PRIVATE KEY")) {
            String pemBody = maybePem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(pemBody);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der));
        }

        // Fallback: assume provided string was the Base64 body already (should have matched DER case)
        // but if not, throw explicit error
        throw new InvalidKeySpecException("Unrecognized private key format. Provide PEM content, Base64 DER, or Base64 of PEM.");
    }

    /**
     * Load public key from PEM string (with or without Base64 encoding).
     */
    private PublicKey loadPublicKey(String keyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Case 1: Direct PEM content
        if (keyString.contains("BEGIN PUBLIC KEY")) {
            String pemBody = keyString
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(pemBody);
            return keyFactory.generatePublic(new X509EncodedKeySpec(der));
        }

        // Case 2: Base64 decode first. It may be DER bytes or PEM text.
        byte[] decoded = Base64.getDecoder().decode(keyString.replaceAll("\\s", ""));
        if (decoded.length > 0 && (decoded[0] & 0xFF) == 0x30) {
            return keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
        }

        String maybePem = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
        if (maybePem.contains("BEGIN PUBLIC KEY")) {
            String pemBody = maybePem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(pemBody);
            return keyFactory.generatePublic(new X509EncodedKeySpec(der));
        }

        throw new InvalidKeySpecException("Unrecognized public key format. Provide PEM content, Base64 DER, or Base64 of PEM.");
    }

    /**
     * Data class for refresh token storage in Redis.
     */
    public static class RefreshTokenData {
        private UUID userId;
        private long issuedAt;
        private long expiresAt;
        private String clientIp;

        public RefreshTokenData() {}

        public RefreshTokenData(UUID userId, long issuedAt, long expiresAt, String clientIp) {
            this.userId = userId;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.clientIp = clientIp;
        }

        // Getters and setters
        public UUID getUserId() { return userId; }
        public void setUserId(UUID userId) { this.userId = userId; }
        public long getIssuedAt() { return issuedAt; }
        public void setIssuedAt(long issuedAt) { this.issuedAt = issuedAt; }
        public long getExpiresAt() { return expiresAt; }
        public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
        public String getClientIp() { return clientIp; }
        public void setClientIp(String clientIp) { this.clientIp = clientIp; }
    }
}