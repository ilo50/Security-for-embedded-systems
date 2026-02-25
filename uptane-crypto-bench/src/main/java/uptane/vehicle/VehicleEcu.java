package uptane.vehicle;

import uptane.crypto.CryptoProfile;
import uptane.model.*;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Vehicle / Primary ECU role.
 *
 * Responsible for the full verification and installation pipeline:
 * 1. Verify the OEM blob signature
 * 2. Verify the Director metadata signature
 * 3. Check metadata freshness (not expired)
 * 4. Select the correct target (hardware ID + anti-rollback)
 * 5. Unwrap the session key
 * 6. Decrypt the firmware payload
 * 7. Validate the decrypted payload against the signed metadata (hash + length)
 */
public class VehicleEcu {

    private final CryptoProfile profile;
    private final KeyPair ecuKeyPair;          // ECU's own key pair (for session key unwrap)
    private final PublicKey oemPublicKey;       // trusted OEM public key
    private final PublicKey directorPublicKey;  // trusted Director public key

    public VehicleEcu(CryptoProfile profile, KeyPair ecuKeyPair,
                      PublicKey oemPublicKey, PublicKey directorPublicKey) {
        this.profile = profile;
        this.ecuKeyPair = ecuKeyPair;
        this.oemPublicKey = oemPublicKey;
        this.directorPublicKey = directorPublicKey;
    }

    /**
     * Attempt to verify and install an update.
     *
     * @param blob     the encrypted update package from the OEM
     * @param metadata the signed targets metadata from the Director
     * @param vehicle  this vehicle's identity and current state
     * @return the installation result (accepted/rejected with reason)
     */
    public InstallResult processUpdate(UpdateBlob blob, TargetsMetadata metadata,
                                       VehicleContext vehicle) {
        // Step 1: Verify blob signature (OEM authenticity)
        boolean blobSigValid = profile.signer().verify(
                blob.signedPayload(), blob.signature().signatureBytes(), oemPublicKey);
        if (!blobSigValid) {
            return InstallResult.rejected("Blob signature verification failed");
        }

        // Step 2: Verify metadata signature (Director authorization)
        boolean metaSigValid = profile.signer().verify(
                metadata.signedPayload(), metadata.signature().signatureBytes(), directorPublicKey);
        if (!metaSigValid) {
            return InstallResult.rejected("Metadata signature verification failed");
        }

        // Step 3: Check freshness
        if (metadata.expires().isBefore(Instant.now())) {
            return InstallResult.rejected("Metadata has expired");
        }

        // Step 4: Select target by hardware ID and anti-rollback
        TargetFile target = null;
        for (TargetFile t : metadata.targets()) {
            if (t.hardwareIds().contains(vehicle.hardwareId())
                    && t.version() > vehicle.currentVersion()) {
                target = t;
                break;
            }
        }
        if (target == null) {
            return InstallResult.rejected("No compatible target found");
        }

        // Step 5: Find our recipient info and unwrap the session key
        RecipientInfo recipientInfo = null;
        for (RecipientInfo r : blob.recipients()) {
            if (r.recipientId().equals(vehicle.recipientId())) {
                recipientInfo = r;
                break;
            }
        }
        if (recipientInfo == null) {
            return InstallResult.rejected("No recipient info for this ECU");
        }

        byte[] sessionKey = profile.keyWrapper().unwrap(
                recipientInfo.wrappedSessionKey(), ecuKeyPair.getPrivate());

        // Step 6: Decrypt the firmware payload
        byte[] ciphertextWithTag = Util.concat(
                blob.ciphertext().payload(), blob.ciphertext().authenticationTag());
        byte[] aad = Util.buildAad(target.filename(), target.version(), target.hardwareIds());
        byte[] decrypted = profile.encryptor().decrypt(
                sessionKey, blob.ciphertext().nonce(), ciphertextWithTag, aad);

        // Step 7: Validate hash and length against signed metadata
        if (decrypted.length != target.length()) {
            return InstallResult.rejected("Payload length mismatch");
        }

        byte[] payloadHash = profile.hasher().hash(decrypted);
        String payloadHashHex = HexFormat.of().formatHex(payloadHash);
        if (!payloadHashHex.equals(target.sha256())) {
            return InstallResult.rejected("Payload hash mismatch");
        }

        return InstallResult.accepted(decrypted);
    }

    /**
     * Result of the vehicle's update verification and installation attempt.
     */
    public record InstallResult(boolean accepted, String reason, byte[] firmware) {

        public static InstallResult accepted(byte[] firmware) {
            return new InstallResult(true, "ACCEPTED", firmware);
        }

        public static InstallResult rejected(String reason) {
            return new InstallResult(false, reason, null);
        }
    }
}
