package uptane.crypto;

/**
 * Abstraction for cryptographic hashing.
 * Used to hash firmware payloads for metadata integrity checks.
 */
public interface Hasher {

    String algorithmName();

    /** Compute the hash of the given data. */
    byte[] hash(byte[] data);
}
