package uptane.model;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Shared helpers: hex encoding, deterministic byte generation, and firmware factory.
 */
public final class Util {

    private Util() {}

    private static final HexFormat HEX = HexFormat.of();

    public static String hex(byte[] data) {
        return HEX.formatHex(data);
    }

    public static byte[] unhex(String s) {
        return HEX.parseHex(s.startsWith("0x") ? s.substring(2) : s);
    }

    /** SHA-256 hash (convenience wrapper). */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Produces deterministic pseudo-random bytes from a seed.
     * Used to create reproducible firmware payloads across runs.
     */
    public static byte[] deterministicBytes(byte[] seed, int length) {
        byte[] output = new byte[length];
        int offset = 0;
        int counter = 0;
        while (offset < length) {
            byte[] block = sha256(concat(seed, intToBytes(counter)));
            int toCopy = Math.min(block.length, length - offset);
            System.arraycopy(block, 0, output, offset, toCopy);
            offset += toCopy;
            counter++;
        }
        return output;
    }

    /** Builds the default ~10 KB simulated firmware image. */
    public static UpdateFirmware defaultFirmware() {
        byte[] manifest = ("target=ECU_Type_A\nversion=2\nsecure_boot=true\n"
                + "anti_rollback=true\nmodule=v2x_comms\n").getBytes(StandardCharsets.UTF_8);

        byte[] header = concat(
                "V2XFWPKG".getBytes(StandardCharsets.UTF_8),
                shortToBytes(2),
                shortToBytes(manifest.length));

        byte[] sections = concat(
                deterministicBytes("uptane-demo-kernel".getBytes(), 4096),
                deterministicBytes("uptane-demo-v2x-stack".getBytes(), 4096),
                deterministicBytes("uptane-demo-calibration".getBytes(), 2048));

        byte[] payload = concat(header, manifest, sections);

        return new UpdateFirmware(
                "firmware_v2.0.bin", 2, List.of("ECU_Type_A"),
                "Adds anti-rollback checks and hardened V2X crypto settings.",
                payload);
    }

    public static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, offset, a.length);
            offset += a.length;
        }
        return result;
    }

    /** Builds the canonical AAD string used during payload encryption/decryption. */
    public static byte[] buildAad(String filename, int version, List<String> hardwareIds) {
        String aad = filename + ":" + version + ":" + String.join(",", hardwareIds);
        return aad.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    private static byte[] shortToBytes(int value) {
        return ByteBuffer.allocate(2).putShort((short) value).array();
    }
}
