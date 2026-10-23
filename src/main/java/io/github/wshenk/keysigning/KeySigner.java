package io.github.wshenk.keysigning;

import java.nio.charset.StandardCharsets;

/** Signs and verifies payloads with a single key pair. Implementations are thread-safe. */
public interface KeySigner {

    /** The algorithm this signer uses. */
    SigningAlgorithm algorithm();

    /** A stable identifier for the public key, suitable for embedding in envelopes. */
    String keyId();

    /** Signs {@code payload} and returns the raw signature bytes. */
    byte[] sign(byte[] payload);

    /** Returns {@code true} if {@code signature} is valid for {@code payload}. */
    boolean verify(byte[] payload, byte[] signature);

    /** Convenience overload that signs the UTF-8 bytes of {@code payload}. */
    default byte[] sign(String payload) {
        return sign(payload.getBytes(StandardCharsets.UTF_8));
    }
}
