package uptane.crypto;

/**
 * Abstraction for authenticated encryption (AEAD).
 * Covers payload encryption (AES-GCM, ChaCha20-Poly1305).
 */
public interface Encryptor {

    String algorithmName();

    /** Required key length in bytes (e.g. 16 for AES-128, 32 for AES-256). */
    int keyLength();

    /** Required nonce length in bytes. */
    int nonceLength();

    /**
     * Encrypt plaintext with associated data.
     * @return ciphertext with appended authentication tag
     */
    byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad);

    /**
     * Decrypt ciphertext (with appended auth tag) and verify associated data.
     * @return plaintext
     */
    byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] aad);
}
