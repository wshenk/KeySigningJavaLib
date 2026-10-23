package io.github.wshenk.keysigning;

/** Unchecked exception thrown when a key or signature operation fails. */
public class SigningException extends RuntimeException {

    public SigningException(String message) {
        super(message);
    }

    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }
}
