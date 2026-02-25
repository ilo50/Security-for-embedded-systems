package uptane.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA-2 family hasher (SHA-256 by default, configurable to SHA-384/SHA-512).
 */
public class Sha2Hasher implements Hasher {

    private final String algorithm;

    public Sha2Hasher() {
        this("SHA-256");
    }

    public Sha2Hasher(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String algorithmName() {
        return algorithm;
    }

    @Override
    public byte[] hash(byte[] data) {
        try {
            return MessageDigest.getInstance(algorithm).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
