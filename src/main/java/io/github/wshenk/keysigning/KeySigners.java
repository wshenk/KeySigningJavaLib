package io.github.wshenk.keysigning;

import io.github.wshenk.keysigning.internal.JcaKeySigner;
import java.security.KeyPair;

/** Factory methods for {@link KeySigner} instances. */
public final class KeySigners {

    private KeySigners() {}

    /** Creates a signer backed by a freshly generated Ed25519 key pair. */
    public static KeySigner ed25519() {
        return generate(SigningAlgorithm.ED25519);
    }

    /** Creates a signer backed by a freshly generated 3072-bit RSA key pair. */
    public static KeySigner rsa() {
        return generate(SigningAlgorithm.RSA_SHA256);
    }

    /** Creates a signer backed by a freshly generated P-256 EC key pair. */
    public static KeySigner ecdsa() {
        return generate(SigningAlgorithm.ECDSA_P256_SHA256);
    }

    /** Creates a signer backed by a freshly generated key pair for {@code algorithm}. */
    public static KeySigner generate(SigningAlgorithm algorithm) {
        return fromEntry(new KeyRing().generate(algorithm));
    }

    /** Creates a signer for an existing key pair. */
    public static KeySigner of(SigningAlgorithm algorithm, KeyPair keyPair) {
        return fromEntry(new KeyRing().add(algorithm, keyPair));
    }

    /** Creates a signer for a key ring entry. */
    public static KeySigner fromEntry(KeyRing.Entry entry) {
        return new JcaKeySigner(entry.algorithm(), entry.keyId(), entry.keyPair());
    }
}
