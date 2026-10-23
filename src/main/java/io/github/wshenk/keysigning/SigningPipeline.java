package io.github.wshenk.keysigning;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.UnaryOperator;

/**
 * Produces and checks {@link SignedEnvelope}s. Optional payload stages run, in order, before the
 * payload is signed — for example to normalise line endings or trim whitespace.
 */
public final class SigningPipeline {

    private final KeySigner signer;
    private final Clock clock;
    private final List<UnaryOperator<byte[]>> stages;

    private SigningPipeline(Builder builder) {
        this.signer = builder.signer;
        this.clock = builder.clock;
        this.stages = List.copyOf(builder.stages);
    }

    public static Builder builder(KeySigner signer) {
        return new Builder(signer);
    }

    public SignedEnvelope seal(byte[] payload) {
        byte[] prepared = payload.clone();
        for (UnaryOperator<byte[]> stage : stages) {
            prepared = stage.apply(prepared);
        }
        var signedAt = clock.instant();
        byte[] input = SignedEnvelope.signingInput(prepared, signer.algorithm(), signer.keyId(), signedAt);
        return new SignedEnvelope(prepared, signer.sign(input), signer.algorithm(), signer.keyId(), signedAt);
    }

    /** Returns {@code true} if {@code envelope} was sealed by this pipeline's key. */
    public boolean open(SignedEnvelope envelope) {
        return envelope.algorithm() == signer.algorithm()
                && envelope.keyId().equals(signer.keyId())
                && signer.verify(envelope.signingInput(), envelope.signature());
    }

    public static final class Builder {
        private final KeySigner signer;
        private Clock clock = Clock.systemUTC();
        private final List<UnaryOperator<byte[]>> stages = new ArrayList<>();

        private Builder(KeySigner signer) {
            this.signer = Objects.requireNonNull(signer, "signer");
        }

        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
            return this;
        }

        public Builder stage(UnaryOperator<byte[]> stage) {
            stages.add(Objects.requireNonNull(stage, "stage"));
            return this;
        }

        public SigningPipeline build() {
            return new SigningPipeline(this);
        }
    }
}
