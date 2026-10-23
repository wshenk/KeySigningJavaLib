package io.github.wshenk.keysigning;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * A payload bundled with its signature and the metadata needed to verify it.
 *
 * @param payload the signed bytes
 * @param signature the raw signature over {@link #signingInput()}
 * @param algorithm the algorithm used
 * @param keyId the id of the signing key
 * @param signedAt when the envelope was created
 */
public record SignedEnvelope(
        byte[] payload, byte[] signature, SigningAlgorithm algorithm, String keyId, Instant signedAt) {

    public SignedEnvelope {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(signature, "signature");
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(signedAt, "signedAt");
        payload = payload.clone();
        signature = signature.clone();
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    /** The exact bytes that were signed: the metadata header followed by the payload. */
    public byte[] signingInput() {
        return signingInput(payload, algorithm, keyId, signedAt);
    }

    static byte[] signingInput(byte[] payload, SigningAlgorithm algorithm, String keyId, Instant signedAt) {
        byte[] header = (algorithm.jcaName() + "|" + keyId + "|" + signedAt.toEpochMilli() + "|")
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] input = Arrays.copyOf(header, header.length + payload.length);
        System.arraycopy(payload, 0, input, header.length, payload.length);
        return input;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SignedEnvelope other
                && Arrays.equals(payload, other.payload)
                && Arrays.equals(signature, other.signature)
                && algorithm == other.algorithm
                && keyId.equals(other.keyId)
                && signedAt.equals(other.signedAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(payload), Arrays.hashCode(signature), algorithm, keyId, signedAt);
    }

    @Override
    public String toString() {
        return "SignedEnvelope[algorithm=" + algorithm + ", keyId=" + keyId + ", signedAt=" + signedAt
                + ", payloadLength=" + payload.length + "]";
    }
}
