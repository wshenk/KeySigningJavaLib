package io.github.wshenk.keysigning;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

/**
 * Encodes envelopes as a single dot-separated, URL-safe line:
 * {@code v1.<algorithm>.<keyId>.<epochMillis>.<payload>.<signature>}.
 */
public final class EnvelopeCodec {

    private static final String VERSION = "v1";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private EnvelopeCodec() {}

    public static String encode(SignedEnvelope envelope) {
        return String.join(".",
                VERSION,
                envelope.algorithm().name(),
                envelope.keyId(),
                Long.toString(envelope.signedAt().toEpochMilli()),
                ENCODER.encodeToString(envelope.payload()),
                ENCODER.encodeToString(envelope.signature()));
    }

    public static SignedEnvelope decode(String encoded) {
        String[] parts = encoded.split("\\.", -1);
        if (parts.length != 6 || !VERSION.equals(parts[0])) {
            throw new SigningException("Malformed envelope");
        }
        try {
            return new SignedEnvelope(
                    DECODER.decode(parts[4]),
                    DECODER.decode(parts[5]),
                    SigningAlgorithm.valueOf(parts[1]),
                    parts[2],
                    Instant.ofEpochMilli(Long.parseLong(parts[3])));
        } catch (IllegalArgumentException e) {
            throw new SigningException("Malformed envelope", e);
        }
    }

    public static byte[] encodeToBytes(SignedEnvelope envelope) {
        return encode(envelope).getBytes(StandardCharsets.US_ASCII);
    }
}
