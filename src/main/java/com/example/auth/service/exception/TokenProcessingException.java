package com.example.auth.service.exception;

/**
 * Exception thrown when JWT token operations fail.
 */
public class TokenProcessingException extends RuntimeException {

    public TokenProcessingException(String message) {
        super(message);
    }

    public TokenProcessingException(String message, Throwable cause) {
        super(message, cause);
    }
}