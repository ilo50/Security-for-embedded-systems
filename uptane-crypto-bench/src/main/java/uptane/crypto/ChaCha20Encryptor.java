package uptane.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 authenticated encryption.
 * An alternative to AES-GCM that performs well on devices without AES hardware acceleration.
 */
public class ChaCha20Encryptor implements Encryptor {

    @Override
    public String algorithmName() {
        return "ChaCha20-Poly1305";
    }

    @Override
    public int keyLength() {
        return 32;
    }

    @Override
    public int nonceLength() {
        return 12;
    }

    @Override
    public byte[] encrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new IvParameterSpec(nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] key, byte[] nonce, byte[] ciphertextWithTag, byte[] aad) {
        try {
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new IvParameterSpec(nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertextWithTag);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
