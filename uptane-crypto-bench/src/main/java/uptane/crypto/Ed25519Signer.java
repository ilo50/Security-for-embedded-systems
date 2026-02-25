package uptane.crypto;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import uptane.model.Util;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ed25519 signing via BouncyCastle.
 * Faster than ECDSA with equivalent security (~128-bit).
 */
public class Ed25519Signer implements Signer {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    @Override
    public String algorithmName() {
        return "Ed25519";
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair deriveKeyPair(String label) {
        try {
            byte[] seed = Util.sha256(label.getBytes());
            Ed25519PrivateKeyParameters privParams = new Ed25519PrivateKeyParameters(seed, 0);
            Ed25519PublicKeyParameters pubParams = privParams.generatePublicKey();

            KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");

            // Build X.509 SubjectPublicKeyInfo for Ed25519
            byte[] pubRaw = pubParams.getEncoded();
            byte[] x509Prefix = new byte[]{
                    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Util.concat(x509Prefix, pubRaw)));

            // Build PKCS#8 for Ed25519 private key (seed form)
            byte[] pkcs8Prefix = new byte[]{
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                    0x04, 0x22, 0x04, 0x20};
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(Util.concat(pkcs8Prefix, seed)));

            return new KeyPair(pub, priv);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature sig = Signature.getInstance("Ed25519", "BC");
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
            Signature sig = Signature.getInstance("Ed25519", "BC");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
