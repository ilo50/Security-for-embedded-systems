package uptane.crypto;

import uptane.model.Util;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECParameterSpec;

/**
 * ECDSA signing with NIST P-256 (secp256r1).
 * This is the Uptane baseline recommendation.
 */
public class EcdsaP256Signer implements Signer {

    private static final BigInteger ORDER = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

    @Override
    public String algorithmName() {
        return "ECDSA-P256";
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyPair deriveKeyPair(String label) {
        try {
            byte[] seed = Util.sha256(label.getBytes());
            BigInteger s = new BigInteger(1, seed).mod(ORDER.subtract(BigInteger.ONE)).add(BigInteger.ONE);

            // Get EC parameters from a generated key pair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec params = ((ECPrivateKey) kpg.generateKeyPair().getPrivate()).getParams();

            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey priv = kf.generatePrivate(new ECPrivateKeySpec(s, params));

            // Derive public key: Q = s * G (using BouncyCastle point multiplication)
            org.bouncycastle.math.ec.ECPoint point = org.bouncycastle.asn1.x9.ECNamedCurveTable
                    .getByName("secp256r1").getG().multiply(s).normalize();

            java.security.spec.ECPoint w = new java.security.spec.ECPoint(
                    point.getAffineXCoord().toBigInteger(),
                    point.getAffineYCoord().toBigInteger());
            PublicKey pub = kf.generatePublic(new java.security.spec.ECPublicKeySpec(w, params));

            return new KeyPair(pub, priv);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
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
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(data);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
