package uptane.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-GCM authenticated encryption.
 * Supports both 128-bit and 256-bit keys (determined by the key passed in).
 */
public class AesGcmEncryptor implements Encryptor {

    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;

    private final int keyLen;

    /** @param keyLen key length in bytes: 16 for AES-128, 32 for AES-256 */
    public AesGcmEncryptor(int keyLen) {
        this.keyLen = keyLen;
    }

    @Override
    public String algorithmName() {
        return "AES-" + (keyLen * 8) + "-GCM";
    }

    @Override
    public int keyLength() {
        return keyLen;
    }

    @Override
    public int nonceLength() {
        return GCM_NONCE_BYTES;
    }

    @Override
    public byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext); // ciphertext + tag appended
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertextWithTag);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
