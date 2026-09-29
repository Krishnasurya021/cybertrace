package com.sentinel.exceptions;

/**
 * OOP Principle: EXCEPTION HANDLING (UNCHECKED EXCEPTION)
 * Thrown when an incoming log line cannot be parsed or lacks mandatory telemetry fields.
 */
public class InvalidLogFormatException extends RuntimeException {
    public InvalidLogFormatException(String message) {
        super(message);
    }

    public InvalidLogFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
