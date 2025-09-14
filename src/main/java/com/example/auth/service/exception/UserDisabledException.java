package com.example.auth.service.exception;

/**
 * Exception thrown when a user account is disabled or locked.
 */
public class UserDisabledException extends RuntimeException {

    public UserDisabledException(String message) {
        super(message);
    }

    public UserDisabledException(String message, Throwable cause) {
        super(message, cause);
    }
}