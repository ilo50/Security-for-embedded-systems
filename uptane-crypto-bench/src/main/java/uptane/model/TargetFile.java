package uptane.model;

import java.util.List;

/**
 * Describes a single firmware target in the Uptane metadata.
 * The vehicle uses this to verify the decrypted payload.
 */
public record TargetFile(
        String filename,
        int length,
        String sha256,
        List<String> hardwareIds,
        int version
) {}
