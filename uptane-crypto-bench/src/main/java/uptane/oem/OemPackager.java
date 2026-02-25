package uptane.oem;

import uptane.crypto.CryptoProfile;
import uptane.model.*;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.List;

/**
 * OEM role (Image Repository).
 *
 * Responsible for:
 * 1. Generating a random session key
 * 2. Encrypting the firmware payload (AEAD)
 * 3. Wrapping the session key for each recipient ECU
 * 4. Signing the entire blob (ciphertext + recipients) with the OEM key
 */
public class OemPackager {

    private final CryptoProfile profile;
    private final KeyPair oemSigningKey;

    public OemPackager(CryptoProfile profile, KeyPair oemSigningKey) {
        this.profile = profile;
        this.oemSigningKey = oemSigningKey;
    }

    /**
     * Package firmware into an encrypted, signed update blob.
     *
     * @param firmware           the plaintext firmware image
     * @param recipientPublicKeys recipient ECU public keys (id → public key)
     * @return the complete update blob ready for distribution
     */
    public UpdateBlob packageFirmware(UpdateFirmware firmware,
                                      List<RecipientEntry> recipientPublicKeys) {
        // Step 1: Generate a random session key
        byte[] sessionKey = new byte[profile.encryptor().keyLength()];
        new SecureRandom().nextBytes(sessionKey);

        // Step 2: Generate nonce and encrypt the firmware payload
        byte[] nonce = new byte[profile.encryptor().nonceLength()];
        new SecureRandom().nextBytes(nonce);
        byte[] aad = Util.buildAad(firmware.filename(), firmware.version(), firmware.hardwareIds());
        byte[] encrypted = profile.encryptor().encrypt(sessionKey, nonce, firmware.payload(), aad);

        // Separate ciphertext body from auth tag (last 16 bytes for GCM/Poly1305)
        int tagLen = 16;
        byte[] body = new byte[encrypted.length - tagLen];
        byte[] tag = new byte[tagLen];
        System.arraycopy(encrypted, 0, body, 0, body.length);
        System.arraycopy(encrypted, body.length, tag, 0, tagLen);

        Ciphertext ciphertext = new Ciphertext(
                profile.encryptor().algorithmName(), nonce, body, tag);

        // Step 3: Wrap the session key for each recipient
        List<RecipientInfo> recipients = recipientPublicKeys.stream()
                .map(entry -> new RecipientInfo(
                        entry.recipientId(),
                        profile.keyWrapper().algorithmName(),
                        profile.keyWrapper().wrap(sessionKey, entry.publicKey())))
                .toList();

        // Step 4: Build canonical payload and sign it
        byte[] signedPayload = canonicalPayload(ciphertext, recipients);
        byte[] sig = profile.signer().sign(signedPayload, oemSigningKey.getPrivate());

        return new UpdateBlob(
                recipients,
                ciphertext,
                new SignatureEntry("OEM_Root_CA_ID", sig),
                signedPayload);
    }

    /** Canonical byte representation of the blob content (for signing/verification). */
    private byte[] canonicalPayload(Ciphertext ct, List<RecipientInfo> recipients) {
        // Simple deterministic encoding: algorithm + nonce + ciphertext + tag + wrapped keys
        byte[][] parts = new byte[3 + recipients.size()][];
        parts[0] = ct.nonce();
        parts[1] = ct.payload();
        parts[2] = ct.authenticationTag();
        for (int i = 0; i < recipients.size(); i++) {
            parts[3 + i] = recipients.get(i).wrappedSessionKey();
        }
        return Util.concat(parts);
    }

    /**
     * A recipient identity paired with their public key.
     */
    public record RecipientEntry(String recipientId, java.security.PublicKey publicKey) {}
}
