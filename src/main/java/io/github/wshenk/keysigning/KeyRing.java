package io.github.wshenk.keysigning;

import io.github.wshenk.keysigning.internal.KeyIds;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** An in-memory collection of key pairs, indexed by key id. */
public final class KeyRing {

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    /** A key pair together with the algorithm it is used for. */
    public record Entry(String keyId, SigningAlgorithm algorithm, KeyPair keyPair) {}

    /** Generates a new key pair for {@code algorithm}, stores it, and returns its entry. */
    public Entry generate(SigningAlgorithm algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.keyAlgorithm());
            if (algorithm.keySize() > 0) {
                generator.initialize(algorithm.keySize());
            }
            return add(algorithm, generator.generateKeyPair());
        } catch (GeneralSecurityException e) {
            throw new SigningException("Could not generate " + algorithm + " key pair", e);
        }
    }

    /** Stores an existing key pair and returns its entry. */
    public Entry add(SigningAlgorithm algorithm, KeyPair keyPair) {
        Entry entry = new Entry(KeyIds.of(keyPair.getPublic()), algorithm, keyPair);
        entries.put(entry.keyId(), entry);
        return entry;
    }

    public Optional<Entry> find(String keyId) {
        return Optional.ofNullable(entries.get(keyId));
    }

    public boolean remove(String keyId) {
        return entries.remove(keyId) != null;
    }

    public int size() {
        return entries.size();
    }
}
