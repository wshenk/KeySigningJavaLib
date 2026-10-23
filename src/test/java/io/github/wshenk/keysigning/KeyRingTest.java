package io.github.wshenk.keysigning;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class KeyRingTest {

    @Test
    void storesAndRemovesEntries() {
        KeyRing ring = new KeyRing();
        KeyRing.Entry entry = ring.generate(SigningAlgorithm.ED25519);

        assertEquals(1, ring.size());
        assertEquals(entry, ring.find(entry.keyId()).orElseThrow());
        assertTrue(ring.remove(entry.keyId()));
        assertFalse(ring.find(entry.keyId()).isPresent());
    }

    @Test
    void keyIdIsStableForTheSameKey() {
        KeyRing.Entry entry = new KeyRing().generate(SigningAlgorithm.ED25519);

        assertEquals(entry.keyId(), KeySigners.of(entry.algorithm(), entry.keyPair()).keyId());
    }
}
