package uptane.director;

import uptane.crypto.CryptoProfile;
import uptane.model.*;

import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;

/**
 * Director role.
 *
 * Responsible for:
 * 1. Hashing the firmware payload
 * 2. Building targets metadata (hash, length, version, hardware IDs, expiry)
 * 3. Signing the metadata with the Director's private key
 *
 * The Director decides WHICH targets are authorized for WHICH vehicles.
 */
public class DirectorService {

    private final CryptoProfile profile;
    private final KeyPair directorSigningKey;

    public DirectorService(CryptoProfile profile, KeyPair directorSigningKey) {
        this.profile = profile;
        this.directorSigningKey = directorSigningKey;
    }

    /**
     * Build and sign targets metadata for a firmware image.
     *
     * @param firmware the firmware whose metadata we are authorizing
     * @return signed targets metadata
     */
    public TargetsMetadata buildTargetsMetadata(UpdateFirmware firmware) {
        // Hash the firmware payload
        byte[] hash = profile.hasher().hash(firmware.payload());
        String hashHex = HexFormat.of().formatHex(hash);

        // Build the target descriptor
        TargetFile target = new TargetFile(
                firmware.filename(),
                firmware.length(),
                hashHex,
                firmware.hardwareIds(),
                firmware.version());

        // Metadata expires 1 year from now
        Instant expires = Instant.now().plus(365, ChronoUnit.DAYS);

        // Build canonical bytes for signing
        byte[] signedPayload = canonicalPayload(expires, List.of(target));

        // Sign with Director key
        byte[] sig = profile.signer().sign(signedPayload, directorSigningKey.getPrivate());

        return new TargetsMetadata(
                expires,
                List.of(target),
                new SignatureEntry("Director_Key_ID", sig),
                signedPayload);
    }

    /** Deterministic canonical representation for signing. */
    private byte[] canonicalPayload(Instant expires, List<TargetFile> targets) {
        StringBuilder sb = new StringBuilder();
        sb.append("expires:").append(expires.toString());
        for (TargetFile t : targets) {
            sb.append("|").append(t.filename())
              .append(":").append(t.length())
              .append(":").append(t.sha256())
              .append(":").append(t.version())
              .append(":").append(String.join(",", t.hardwareIds()));
        }
        return sb.toString().getBytes();
    }
}
