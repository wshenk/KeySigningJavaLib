# KeySigningJavaLib

A small, JDK-only Java 21 library for signing and verifying payloads with Ed25519, RSA, or ECDSA.

## Usage

```java
KeySigner signer = KeySigners.ed25519();
byte[] signature = signer.sign("hello");
boolean ok = signer.verify("hello".getBytes(UTF_8), signature);

SigningPipeline pipeline = SigningPipeline.builder(signer).build();
String token = EnvelopeCodec.encode(pipeline.seal(payload));
boolean valid = pipeline.open(EnvelopeCodec.decode(token));
```

## Building the package

```sh
./gradlew build                                   # compile, test, javadoc
./gradlew publishAllPublicationsToBuildRepository # Maven layout in build/repo/
./gradlew publishToMavenLocal                     # install into ~/.m2
```

Coordinates: `io.github.wshenk:keysigning:<version>` (version in `gradle.properties`).

CI (`.github/workflows/build.yml`) builds on every push and uploads `build/repo/` as the
`keysigning-package` workflow artifact.
