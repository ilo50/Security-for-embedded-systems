package uptane.model;

/**
 * Per-ECU session key delivery info.
 * Contains the wrapped (encrypted) session key that only the target ECU can unwrap.
 */
public record RecipientInfo(
        String recipientId,
        String keyEncryptionAlgorithm,
        byte[] wrappedSessionKey
) {}
