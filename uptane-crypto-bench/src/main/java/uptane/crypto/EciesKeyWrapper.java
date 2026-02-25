package uptane.crypto;

import uptane.model.Util;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

/**
 * ECIES-style key wrapping: ECDH key agreement + HKDF-SHA256 + AES-GCM wrap.
 * Mirrors the Python ECIES construction for the NIST P-256 baseline.
 *
 * Wrapped output format: [65-byte ephemeral public key][12-byte nonce][encrypted session key + 16-byte tag]
 */
public class EciesKeyWrapper implements KeyWrapper {

    private static final BigInteger ORDER = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    @Override
    public String algorithmName() {
        return "ECIES-P256";
    }

    @Override
    public KeyPair generateRecipientKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair deriveRecipientKeyPair(String label) {
        // Reuse the same derivation logic as EcdsaP256Signer
        return new EcdsaP256Signer().deriveKeyPair(label);
    }

    @Override
    public byte[] wrap(byte[] sessionKey, PublicKey recipientPublicKey) {
        try {
            // Generate ephemeral key pair for this wrap operation
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair ephemeral = kpg.generateKeyPair();

            // ECDH shared secret
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(ephemeral.getPrivate());
            ka.doPhase(recipientPublicKey, true);
            byte[] sharedSecret = ka.generateSecret();

            // HKDF-SHA256 to derive the wrapping key
            byte[] wrappingKey = hkdfSha256(sharedSecret, 32);

            // AES-GCM wrap the session key
            byte[] nonce = new byte[12];
            new SecureRandom().nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(wrappingKey, "AES"),
                    new GCMParameterSpec(128, nonce));
            byte[] wrapped = cipher.doFinal(sessionKey);

            // Encode ephemeral public key as uncompressed point (65 bytes for P-256)
            ECPublicKey ecPub = (ECPublicKey) ephemeral.getPublic();
            byte[] ephPub = encodeUncompressed(ecPub);

            return Util.concat(ephPub, nonce, wrapped);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] unwrap(byte[] wrappedKey, PrivateKey recipientPrivateKey) {
        try {
            // Parse: [65 ephemeral pub][12 nonce][rest = encrypted key + tag]
            byte[] ephPubBytes = new byte[65];
            byte[] nonce = new byte[12];
            System.arraycopy(wrappedKey, 0, ephPubBytes, 0, 65);
            System.arraycopy(wrappedKey, 65, nonce, 0, 12);
            byte[] encryptedKey = new byte[wrappedKey.length - 77];
            System.arraycopy(wrappedKey, 77, encryptedKey, 0, encryptedKey.length);

            // Reconstruct ephemeral public key
            PublicKey ephPub = decodeUncompressed(ephPubBytes);

            // ECDH
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(recipientPrivateKey);
            ka.doPhase(ephPub, true);
            byte[] sharedSecret = ka.generateSecret();

            // HKDF
            byte[] wrappingKey = hkdfSha256(sharedSecret, 32);

            // AES-GCM unwrap
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(wrappingKey, "AES"),
                    new GCMParameterSpec(128, nonce));
            return cipher.doFinal(encryptedKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Simplified HKDF-SHA256 extract-and-expand (single block, no salt/info). */
    private byte[] hkdfSha256(byte[] ikm, int length) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            // Extract: PRK = HMAC(salt, IKM) — using zero salt
            mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);

            // Expand: OKM = HMAC(PRK, 0x01)
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] okm = mac.doFinal(new byte[]{0x01});

            byte[] result = new byte[length];
            System.arraycopy(okm, 0, result, 0, length);
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Encode an EC public key as an uncompressed point (0x04 || x || y). */
    private byte[] encodeUncompressed(ECPublicKey pub) {
        byte[] x = toFixedBytes(pub.getW().getAffineX(), 32);
        byte[] y = toFixedBytes(pub.getW().getAffineY(), 32);
        byte[] result = new byte[65];
        result[0] = 0x04;
        System.arraycopy(x, 0, result, 1, 32);
        System.arraycopy(y, 0, result, 33, 32);
        return result;
    }

    /** Decode an uncompressed EC point back to a PublicKey. */
    private PublicKey decodeUncompressed(byte[] encoded) throws Exception {
        byte[] x = new byte[32], y = new byte[32];
        System.arraycopy(encoded, 1, x, 0, 32);
        System.arraycopy(encoded, 33, y, 0, 32);

        ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec params = ((ECPrivateKey) kpg.generateKeyPair().getPrivate()).getParams();

        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, params));
    }

    /** Convert a BigInteger to a fixed-length byte array (pad or trim leading zeros). */
    private byte[] toFixedBytes(BigInteger val, int len) {
        byte[] raw = val.toByteArray();
        if (raw.length == len) return raw;
        byte[] result = new byte[len];
        if (raw.length > len) {
            System.arraycopy(raw, raw.length - len, result, 0, len);
        } else {
            System.arraycopy(raw, 0, result, len - raw.length, raw.length);
        }
        return result;
    }
}
