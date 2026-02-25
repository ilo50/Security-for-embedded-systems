package uptane.crypto;

/**
 * Bundles a complete set of cryptographic primitives into a named profile.
 * The OEM, Director, and Vehicle roles all receive the same profile so
 * their algorithms stay aligned.
 */
public record CryptoProfile(
        String name,
        Signer signer,
        Encryptor encryptor,
        KeyWrapper keyWrapper,
        Hasher hasher
) {
    @Override
    public String toString() {
        return name;
    }
}
