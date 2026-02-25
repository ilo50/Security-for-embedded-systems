package uptane.crypto;

import uptane.model.Util;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * RSA-PSS signing with configurable key size (2048 or 3072 bits).
 * PSS is the recommended padding mode for new implementations.
 */
public class RsaSigner implements Signer {

    private final int keySize;

    public RsaSigner(int keySize) {
        if (keySize != 2048 && keySize != 3072) {
            throw new IllegalArgumentException("Supported key sizes: 2048, 3072");
        }
        this.keySize = keySize;
    }

    @Override
    public String algorithmName() {
        return "RSA-" + keySize + "-PSS";
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * For RSA, deterministic derivation isn't practical the same way as ECC.
     * We use a seeded SecureRandom to get reproducible key pairs for simulation.
     */
    @Override
    public KeyPair deriveKeyPair(String label) {
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
    public byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature sig = Signature.getInstance("RSASSA-PSS");
            sig.setParameter(new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            sig.initSign(privateKey);
            sig.update(data);
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("RSASSA-PSS");
            sig.setParameter(new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
