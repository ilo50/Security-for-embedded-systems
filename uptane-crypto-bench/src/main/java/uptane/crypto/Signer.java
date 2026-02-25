package uptane.crypto;

import java.security.KeyPair;

/**
 * Abstraction for digital signature operations.
 * Each implementation provides a different algorithm (ECDSA, Ed25519, RSA).
 */
public interface Signer {

    /** Human-readable algorithm name for display in benchmark results. */
    String algorithmName();

    /** Generate a fresh key pair suitable for this signing scheme. */
    KeyPair generateKeyPair();

    /**
     * Derive a deterministic key pair from a label string.
     * Used for reproducible simulation — NOT suitable for production.
     */
    KeyPair deriveKeyPair(String label);

    /** Sign the given data using the private key. */
    byte[] sign(byte[] data, java.security.PrivateKey privateKey);

    /** Verify a signature against the given data and public key. */
    boolean verify(byte[] data, byte[] signature, java.security.PublicKey publicKey);
}
