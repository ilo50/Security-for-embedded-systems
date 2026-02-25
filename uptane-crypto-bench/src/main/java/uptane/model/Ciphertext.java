package uptane.model;

/**
 * Encrypted firmware payload with its AEAD nonce and authentication tag.
 */
public record Ciphertext(
        String symmetricAlgorithm,
        byte[] nonce,
        byte[] payload,
        byte[] authenticationTag
) {}
