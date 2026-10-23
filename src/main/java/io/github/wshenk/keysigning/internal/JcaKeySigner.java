package io.github.wshenk.keysigning.internal;

import io.github.wshenk.keysigning.KeySigner;
import io.github.wshenk.keysigning.SigningAlgorithm;
import io.github.wshenk.keysigning.SigningException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.SignatureException;

/** {@link KeySigner} backed by {@link java.security.Signature}. Not part of the public API. */
public final class JcaKeySigner implements KeySigner {

    private final SigningAlgorithm algorithm;
    private final String keyId;
    private final KeyPair keyPair;

    public JcaKeySigner(SigningAlgorithm algorithm, String keyId, KeyPair keyPair) {
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.keyPair = keyPair;
    }

    @Override
    public SigningAlgorithm algorithm() {
        return algorithm;
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public byte[] sign(byte[] payload) {
        try {
            Signature signature = Signature.getInstance(algorithm.jcaName());
            signature.initSign(keyPair.getPrivate());
            signature.update(payload);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new SigningException("Signing with " + algorithm + " failed", e);
        }
    }

    @Override
    public boolean verify(byte[] payload, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance(algorithm.jcaName());
            signature.initVerify(keyPair.getPublic());
            signature.update(payload);
            return signature.verify(signatureBytes);
        } catch (SignatureException e) {
            // Malformed signature bytes (e.g. bad DER for ECDSA) simply don't verify.
            return false;
        } catch (GeneralSecurityException e) {
            throw new SigningException("Verification with " + algorithm + " failed", e);
        }
    }
}
