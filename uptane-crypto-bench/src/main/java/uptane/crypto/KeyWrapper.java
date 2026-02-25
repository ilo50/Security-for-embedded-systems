package uptane.crypto;

import java.security.KeyPair;

/**
 * Abstraction for session-key wrapping/unwrapping.
 * In Uptane, the OEM wraps a session key so only the target ECU can recover it.
 * Implementations: ECIES (ECDH + HKDF + AEAD) or RSA-OAEP.
 */
public interface KeyWrapper {

    String algorithmName();

    /** Generate a key pair for the recipient (ECU). */
    KeyPair generateRecipientKeyPair();

    /** Deterministic key pair for reproducible simulation. */
    KeyPair deriveRecipientKeyPair(String label);

    /**
     * Wrap (encrypt) the session key for a specific recipient.
     * @param sessionKey    the symmetric key to protect
     * @param recipientPublicKey   recipient's public key
     * @return opaque wrapped key bytes (format is implementation-specific)
     */
    byte[] wrap(byte[] sessionKey, java.security.PublicKey recipientPublicKey);

    /**
     * Unwrap (decrypt) the session key using the recipient's private key.
     * @param wrappedKey    output from {@link #wrap}
     * @param recipientPrivateKey  recipient's private key
     * @return the original session key
     */
    byte[] unwrap(byte[] wrappedKey, java.security.PrivateKey recipientPrivateKey);
}
