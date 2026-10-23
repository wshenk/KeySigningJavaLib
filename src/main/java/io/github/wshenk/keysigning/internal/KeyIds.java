package io.github.wshenk.keysigning.internal;

import io.github.wshenk.keysigning.SigningException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;

/** Derives short, stable key ids from public keys. Not part of the public API. */
public final class KeyIds {

    private static final int ID_BYTES = 8;

    private KeyIds() {}

    /** Returns the first 8 bytes of the SHA-256 of the key's encoded form, as lowercase hex. */
    public static String of(PublicKey key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
            return HexFormat.of().formatHex(digest, 0, ID_BYTES);
        } catch (NoSuchAlgorithmException e) {
            throw new SigningException("SHA-256 is not available", e);
        }
    }
}
