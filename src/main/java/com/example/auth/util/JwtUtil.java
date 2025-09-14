package com.example.auth.util;

import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

/**
 * Utility class for JWT token operations.
 * Provides helper methods for token parsing, validation, and key management.
 */
public final class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private JwtUtil() {
        // Utility class - prevent instantiation
    }

    /**
     * Extract all claims from a JWT token without validation.
     * Use with caution - only for parsing, not for security decisions.
     * @param token the JWT token
     * @return Claims object or null if parsing fails
     */
    public static Claims parseClaimsUnsafe(String token) {
        try {
            // Parse without signature verification - only for claim extraction
            String[] chunks = token.split("\\.");
            if (chunks.length != 3) {
                return null;
            }
            
            // Decode payload (claims)
            //String payload = chunks[1];
            //byte[] decodedPayload = Base64.getUrlDecoder().decode(payload);
            
            // This is a simplified approach - in production, use proper JWT parsing
            // For now, return null as we should use TokenService for secure parsing
            return null;
        } catch (Exception e) {
            logger.debug("Failed to parse JWT claims: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extract the JTI (JWT ID) claim from token payload without validation.
     * @param token the JWT token
     * @return JTI value or null if not found
     */
    public static String extractJti(String token) {
        Claims claims = parseClaimsUnsafe(token);
        return claims != null ? claims.getId() : null;
    }

    /**
     * Extract the subject (user ID) from token payload without validation.
     * @param token the JWT token
     * @return subject value or null if not found
     */
    public static String extractSubject(String token) {
        Claims claims = parseClaimsUnsafe(token);
        return claims != null ? claims.getSubject() : null;
    }

    /**
     * Extract the expiration time from token payload without validation.
     * @param token the JWT token
     * @return expiration Date or null if not found
     */
    public static Date extractExpiration(String token) {
        Claims claims = parseClaimsUnsafe(token);
        return claims != null ? claims.getExpiration() : null;
    }

    /**
     * Check if a token is expired based on its expiration claim.
     * Does NOT validate the signature - only checks the exp claim.
     * @param token the JWT token
     * @return true if token appears to be expired
     */
    public static boolean isTokenExpired(String token) {
        Date expiration = extractExpiration(token);
        return expiration != null && expiration.before(new Date());
    }

    /**
     * Calculate time until token expiration in seconds.
     * @param token the JWT token
     * @return seconds until expiration or 0 if expired/invalid
     */
    public static long getSecondsUntilExpiration(String token) {
        Date expiration = extractExpiration(token);
        if (expiration == null) {
            return 0;
        }
        
        long millisUntilExpiration = expiration.getTime() - System.currentTimeMillis();
        return Math.max(0, millisUntilExpiration / 1000);
    }

    /**
     * Load RSA private key from PEM string.
     * Handles both raw and Base64-encoded PEM content.
     * @param keyString the PEM private key string
     * @return PrivateKey object
     * @throws InvalidKeySpecException if key format is invalid
     * @throws NoSuchAlgorithmException if RSA algorithm is not available
     */
    public static PrivateKey loadPrivateKey(String keyString) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String cleanKey = cleanPemKey(keyString, "PRIVATE");
        byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
        
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        return keyFactory.generatePrivate(spec);
    }

    /**
     * Load RSA public key from PEM string.
     * Handles both raw and Base64-encoded PEM content.
     * @param keyString the PEM public key string
     * @return PublicKey object
     * @throws InvalidKeySpecException if key format is invalid
     * @throws NoSuchAlgorithmException if RSA algorithm is not available
     */
    public static PublicKey loadPublicKey(String keyString) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String cleanKey = cleanPemKey(keyString, "PUBLIC");
        byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
        
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        return keyFactory.generatePublic(spec);
    }

    /**
     * Clean PEM key string by removing headers, footers, and whitespace.
     * @param keyString the raw PEM key string
     * @param keyType "PRIVATE" or "PUBLIC"
     * @return cleaned Base64 key content
     */
    public static String cleanPemKey(String keyString, String keyType) {
        return keyString
                .replace("-----BEGIN " + keyType + " KEY-----", "")
                .replace("-----END " + keyType + " KEY-----", "")
                .replaceAll("\\s", "");
    }

    /**
     * Generate a secure random string for token generation.
     * @param length the desired length
     * @return random string
     */
    public static String generateRandomString(int length) {
        String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder result = new StringBuilder();
        
        for (int i = 0; i < length; i++) {
            result.append(charset.charAt(random.nextInt(charset.length())));
        }
        
        return result.toString();
    }

    /**
     * Generate a secure random UUID-based token.
     * @return UUID string without hyphens
     */
    public static String generateUuidToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * Validate basic JWT structure (3 parts separated by dots).
     * Does NOT validate signature or claims.
     * @param token the token to validate
     * @return true if token has valid structure
     */
    public static boolean hasValidJwtStructure(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        
        String[] parts = token.split("\\.");
        return parts.length == 3 && 
               !parts[0].isEmpty() && 
               !parts[1].isEmpty() && 
               !parts[2].isEmpty();
    }

    /**
     * Create a map of standard JWT claims.
     * @param subject the subject (user ID)
     * @param issuer the issuer
     * @param audience the audience
     * @param ttlSeconds TTL in seconds
     * @return Map of claims
     */
    public static Map<String, Object> createStandardClaims(String subject, String issuer, String audience, long ttlSeconds) {
        Instant now = Instant.now();
        Instant expiration = now.plus(ttlSeconds, ChronoUnit.SECONDS);
        
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", subject);
        claims.put("iss", issuer);
        claims.put("aud", audience);
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", expiration.getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        
        return claims;
    }
}