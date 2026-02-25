package uptane.model;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Plaintext firmware image before encryption.
 * Represents the binary that the OEM wants to deliver to an ECU.
 */
public record UpdateFirmware(
        String filename,
        int version,
        List<String> hardwareIds,
        String releaseNotes,
        byte[] payload
) {
    public int length() {
        return payload.length;
    }

    /** SHA-256 hex digest of the raw payload. */
    public String sha256() {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(payload);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
