package io.github.wshenk.keysigning;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class SigningPipelineTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private final KeySigner signer = KeySigners.ed25519();
    private final SigningPipeline pipeline = SigningPipeline.builder(signer)
            .clock(Clock.fixed(NOW, ZoneOffset.UTC))
            .stage(bytes -> new String(bytes, StandardCharsets.UTF_8).strip().getBytes(StandardCharsets.UTF_8))
            .build();

    @Test
    void sealedEnvelopeOpens() {
        SignedEnvelope envelope = pipeline.seal("  payload \n".getBytes(StandardCharsets.UTF_8));

        assertTrue(pipeline.open(envelope));
        assertArrayEquals("payload".getBytes(StandardCharsets.UTF_8), envelope.payload());
        assertEquals(NOW, envelope.signedAt());
        assertEquals(signer.keyId(), envelope.keyId());
    }

    @Test
    void envelopeSurvivesEncoding() {
        SignedEnvelope envelope = pipeline.seal("payload".getBytes(StandardCharsets.UTF_8));
        SignedEnvelope decoded = EnvelopeCodec.decode(EnvelopeCodec.encode(envelope));

        assertEquals(envelope, decoded);
        assertTrue(pipeline.open(decoded));
    }

    @Test
    void alteredTimestampIsRejected() {
        SignedEnvelope envelope = pipeline.seal("payload".getBytes(StandardCharsets.UTF_8));
        SignedEnvelope altered = new SignedEnvelope(envelope.payload(), envelope.signature(),
                envelope.algorithm(), envelope.keyId(), NOW.plusSeconds(1));

        assertFalse(pipeline.open(altered));
    }

    @Test
    void malformedEncodingIsRejected() {
        assertThrows(SigningException.class, () -> EnvelopeCodec.decode("v1.not.enough"));
        assertThrows(SigningException.class, () -> EnvelopeCodec.decode("v1.NOPE.id.0.AA.AA"));
    }
}
