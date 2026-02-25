package uptane.crypto;

import uptane.model.Util;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * RSA-OAEP key wrapping.
 * The session key is directly encrypted with the recipient's RSA public key.
 * Simpler than ECIES but produces larger wrapped output (= RSA key size).
 */
public class RsaKeyWrapper implements KeyWrapper {

    private final int keySize;

    public RsaKeyWrapper(int keySize) {
        this.keySize = keySize;
    }

    @Override
    public String algorithmName() {
        return "RSA-" + keySize + "-OAEP";
    }

    @Override
    public KeyPair generateRecipientKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair deriveRecipientKeyPair(String label) {
        try {
            byte[] seed = Util.sha256(label.getBytes());
            SecureRandom seeded = SecureRandom.getInstance("SHA1PRNG");
            seeded.setSeed(seed);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4), seeded);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] wrap(byte[] sessionKey, PublicKey recipientPublicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.WRAP_MODE, recipientPublicKey,
                    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT));
            return cipher.wrap(new javax.crypto.spec.SecretKeySpec(sessionKey, "AES"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] unwrap(byte[] wrappedKey, PrivateKey recipientPrivateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.UNWRAP_MODE, recipientPrivateKey,
                    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT));
            return cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
