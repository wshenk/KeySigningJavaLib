package io.github.wshenk.keysigning;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class KeySignerTest {

    private static final byte[] PAYLOAD = "hello, keysigning".getBytes(StandardCharsets.UTF_8);

    @ParameterizedTest
    @EnumSource(SigningAlgorithm.class)
    void signatureVerifies(SigningAlgorithm algorithm) {
        KeySigner signer = KeySigners.generate(algorithm);

        assertTrue(signer.verify(PAYLOAD, signer.sign(PAYLOAD)));
        assertEquals(algorithm, signer.algorithm());
        assertEquals(16, signer.keyId().length());
    }

    @ParameterizedTest
    @EnumSource(SigningAlgorithm.class)
    void tamperedPayloadIsRejected(SigningAlgorithm algorithm) {
        KeySigner signer = KeySigners.generate(algorithm);
        byte[] signature = signer.sign(PAYLOAD);
        byte[] tampered = PAYLOAD.clone();
        tampered[0] ^= 1;

        assertFalse(signer.verify(tampered, signature));
    }

    @ParameterizedTest
    @EnumSource(SigningAlgorithm.class)
    void otherKeyIsRejected(SigningAlgorithm algorithm) {
        byte[] signature = KeySigners.generate(algorithm).sign(PAYLOAD);

        assertFalse(KeySigners.generate(algorithm).verify(PAYLOAD, signature));
    }
}
