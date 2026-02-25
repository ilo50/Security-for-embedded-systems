package uptane.crypto;

import java.util.List;

/**
 * Pre-configured crypto profiles for benchmarking.
 * Each profile bundles a signing algorithm, AEAD cipher, key wrapper, and hasher.
 */
public final class Profiles {

    private Profiles() {}

    /** ECDSA P-256 + AES-256-GCM + ECIES — the Uptane baseline. */
    public static final CryptoProfile BASELINE_P256 = new CryptoProfile(
            "BASELINE_P256",
            new EcdsaP256Signer(),
            new AesGcmEncryptor(32),
            new EciesKeyWrapper(),
            new Sha2Hasher());

    /** Ed25519 + AES-256-GCM + ECIES P-256. */
    public static final CryptoProfile ED25519_AES256 = new CryptoProfile(
            "ED25519_AES256",
            new Ed25519Signer(),
            new AesGcmEncryptor(32),
            new EciesKeyWrapper(),
            new Sha2Hasher());

    /** RSA-2048 PSS + AES-128-GCM + RSA-OAEP. */
    public static final CryptoProfile RSA2048_AES128 = new CryptoProfile(
            "RSA2048_AES128",
            new RsaSigner(2048),
            new AesGcmEncryptor(16),
            new RsaKeyWrapper(2048),
            new Sha2Hasher());

    /** RSA-3072 PSS + AES-256-GCM + RSA-OAEP. */
    public static final CryptoProfile RSA3072_AES256 = new CryptoProfile(
            "RSA3072_AES256",
            new RsaSigner(3072),
            new AesGcmEncryptor(32),
            new RsaKeyWrapper(3072),
            new Sha2Hasher());

    /** ECDSA P-256 + ChaCha20-Poly1305 + ECIES. */
    public static final CryptoProfile P256_CHACHA = new CryptoProfile(
            "P256_CHACHA",
            new EcdsaP256Signer(),
            new ChaCha20Encryptor(),
            new EciesKeyWrapper(),
            new Sha2Hasher());

    /** All profiles in order. */
    public static List<CryptoProfile> all() {
        return List.of(BASELINE_P256, ED25519_AES256, RSA2048_AES128, RSA3072_AES256, P256_CHACHA);
    }
}
