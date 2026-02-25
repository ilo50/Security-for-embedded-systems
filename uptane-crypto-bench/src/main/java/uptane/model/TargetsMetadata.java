package uptane.model;

import java.time.Instant;
import java.util.List;

/**
 * Signed targets metadata produced by the Director.
 * Lists which firmware targets are authorized for installation,
 * along with expiry and the Director's signature.
 */
public record TargetsMetadata(
        Instant expires,
        List<TargetFile> targets,
        SignatureEntry signature,
        byte[] signedPayload  // canonical bytes that were signed (for verification)
) {}
