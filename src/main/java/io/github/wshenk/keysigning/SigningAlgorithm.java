package io.github.wshenk.keysigning;

/** Signature algorithms supported by this library. All are provided by the standard JDK. */
public enum SigningAlgorithm {
    ED25519("Ed25519", "Ed25519", 0),
    RSA_SHA256("SHA256withRSA", "RSA", 3072),
    ECDSA_P256_SHA256("SHA256withECDSA", "EC", 256);

    private final String jcaName;
    private final String keyAlgorithm;
    private final int keySize;

    SigningAlgorithm(String jcaName, String keyAlgorithm, int keySize) {
        this.jcaName = jcaName;
        this.keyAlgorithm = keyAlgorithm;
        this.keySize = keySize;
    }

    /** The name passed to {@link java.security.Signature#getInstance(String)}. */
    public String jcaName() {
        return jcaName;
    }

    /** The name passed to {@link java.security.KeyPairGenerator#getInstance(String)}. */
    public String keyAlgorithm() {
        return keyAlgorithm;
    }

    /** The key size used for generation, or {@code 0} if the algorithm has a fixed size. */
    public int keySize() {
        return keySize;
    }

    /** Looks up an algorithm by its JCA name, ignoring case. */
    public static SigningAlgorithm fromJcaName(String name) {
        for (SigningAlgorithm algorithm : values()) {
            if (algorithm.jcaName.equalsIgnoreCase(name)) {
                return algorithm;
            }
        }
        throw new SigningException("Unsupported signing algorithm: " + name);
    }
}
