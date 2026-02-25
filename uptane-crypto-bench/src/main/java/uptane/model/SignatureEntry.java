package uptane.model;

/**
 * A cryptographic signature with the signer's key identifier.
 */
public record SignatureEntry(
        String keyId,
        byte[] signatureBytes
) {}
