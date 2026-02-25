package uptane.model;

import java.util.List;

/**
 * The encrypted update package produced by the OEM.
 * Contains the encrypted firmware, per-recipient wrapped keys, and the OEM signature.
 */
public record UpdateBlob(
        List<RecipientInfo> recipients,
        Ciphertext ciphertext,
        SignatureEntry signature,
        byte[] signedPayload  // canonical bytes that were signed (for verification)
) {}
