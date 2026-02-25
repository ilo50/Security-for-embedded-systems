package uptane.benchmark;

import uptane.crypto.CryptoProfile;
import uptane.director.DirectorService;
import uptane.model.*;
import uptane.oem.OemPackager;
import uptane.oem.OemPackager.RecipientEntry;
import uptane.vehicle.VehicleEcu;
import uptane.vehicle.VehicleEcu.InstallResult;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs the full OEM → Director → Vehicle flow for a given crypto profile,
 * measuring wall-clock time for each cryptographic phase.
 */
public class BenchmarkRunner {

    private static final int WARMUP_ITERATIONS = 5;

    private final int iterations;

    public BenchmarkRunner(int iterations) {
        this.iterations = iterations;
    }

    /**
     * Benchmark a single crypto profile end-to-end.
     *
     * @param profile  the crypto profile to measure
     * @param firmware the firmware payload (same across all profiles for fair comparison)
     * @return aggregated results (median timings)
     */
    public BenchmarkResult run(CryptoProfile profile, UpdateFirmware firmware) {
        VehicleContext vehicle = new VehicleContext("VIN_5566_HASH", "ECU_Type_A", 1);

        // Pre-generate keys once (not part of per-operation timing)
        KeyPair oemKey = profile.signer().generateKeyPair();
        KeyPair directorKey = profile.signer().generateKeyPair();
        KeyPair ecuKey = profile.keyWrapper().generateRecipientKeyPair();

        // Warmup: let JIT compile hot paths
        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            runSingleIteration(profile, firmware, vehicle, oemKey, directorKey, ecuKey);
        }

        // Collect timings
        List<long[]> allTimings = new ArrayList<>();
        int sigBytes = 0, ctBytes = 0, wrappedKeyBytes = 0;

        for (int i = 0; i < iterations; i++) {
            TimedRun run = runSingleIteration(profile, firmware, vehicle, oemKey, directorKey, ecuKey);
            allTimings.add(run.timings);

            if (i == 0) {
                // Capture sizes from first run (constant across iterations)
                sigBytes = run.blob.signature().signatureBytes().length;
                ctBytes = run.blob.ciphertext().payload().length
                        + run.blob.ciphertext().authenticationTag().length;
                wrappedKeyBytes = run.blob.recipients().get(0).wrappedSessionKey().length;
            }
        }

        // Compute medians
        BenchmarkResult result = new BenchmarkResult(profile.name());
        String[] metricNames = {
                "OEM Encrypt", "OEM KeyWrap", "OEM Sign",
                "Dir Hash", "Dir Sign",
                "ECU VerifyBlob", "ECU VerifyMeta", "ECU Unwrap", "ECU Decrypt", "ECU HashCheck"
        };

        for (int m = 0; m < metricNames.length; m++) {
            final int idx = m;
            long median = median(allTimings.stream().mapToLong(t -> t[idx]).sorted().toArray());
            result.recordTimeNanos(metricNames[m], median);
        }

        result.recordSize("Signature", sigBytes);
        result.recordSize("Ciphertext", ctBytes);
        result.recordSize("WrappedKey", wrappedKeyBytes);

        return result;
    }

    /** Represents timing data from a single iteration plus the generated artifacts. */
    private record TimedRun(long[] timings, UpdateBlob blob) {}

    /**
     * Execute one complete OEM → Director → Vehicle flow, timing each phase.
     */
    private TimedRun runSingleIteration(CryptoProfile profile, UpdateFirmware firmware,
                                        VehicleContext vehicle, KeyPair oemKey,
                                        KeyPair directorKey, KeyPair ecuKey) {
        long[] t = new long[10];
        int idx = 0;

        // --- OEM side ---
        OemPackager oem = new OemPackager(profile, oemKey);
        List<RecipientEntry> recipients = List.of(
                new RecipientEntry(vehicle.recipientId(), ecuKey.getPublic()));

        // We need to time individual crypto operations within OemPackager.
        // For cleaner timing, we call the crypto primitives directly.

        // OEM: Encrypt payload
        byte[] sessionKey = new byte[profile.encryptor().keyLength()];
        byte[] nonce = new byte[profile.encryptor().nonceLength()];
        byte[] aad = Util.buildAad(firmware.filename(), firmware.version(), firmware.hardwareIds());

        long start = System.nanoTime();
        byte[] encrypted = profile.encryptor().encrypt(sessionKey, nonce, firmware.payload(), aad);
        t[idx++] = System.nanoTime() - start;

        // OEM: Wrap session key
        start = System.nanoTime();
        byte[] wrappedKey = profile.keyWrapper().wrap(sessionKey, ecuKey.getPublic());
        t[idx++] = System.nanoTime() - start;

        // OEM: Sign blob
        // Build the blob first to get the signing payload
        int tagLen = 16;
        byte[] body = new byte[encrypted.length - tagLen];
        byte[] tag = new byte[tagLen];
        System.arraycopy(encrypted, 0, body, 0, body.length);
        System.arraycopy(encrypted, body.length, tag, 0, tagLen);
        byte[] signPayload = Util.concat(nonce, body, tag, wrappedKey);

        start = System.nanoTime();
        byte[] blobSig = profile.signer().sign(signPayload, oemKey.getPrivate());
        t[idx++] = System.nanoTime() - start;

        Ciphertext ct = new Ciphertext(profile.encryptor().algorithmName(), nonce, body, tag);
        RecipientInfo ri = new RecipientInfo(vehicle.recipientId(),
                profile.keyWrapper().algorithmName(), wrappedKey);
        UpdateBlob blob = new UpdateBlob(List.of(ri), ct,
                new SignatureEntry("OEM_Root_CA_ID", blobSig), signPayload);

        // --- Director side ---
        start = System.nanoTime();
        byte[] fwHash = profile.hasher().hash(firmware.payload());
        t[idx++] = System.nanoTime() - start;

        // Director: Sign metadata
        String hashHex = java.util.HexFormat.of().formatHex(fwHash);
        TargetFile target = new TargetFile(firmware.filename(), firmware.length(),
                hashHex, firmware.hardwareIds(), firmware.version());
        java.time.Instant expires = java.time.Instant.now().plus(365, java.time.temporal.ChronoUnit.DAYS);

        byte[] metaPayload = buildMetaPayload(expires, target);
        start = System.nanoTime();
        byte[] metaSig = profile.signer().sign(metaPayload, directorKey.getPrivate());
        t[idx++] = System.nanoTime() - start;

        TargetsMetadata metadata = new TargetsMetadata(expires, List.of(target),
                new SignatureEntry("Director_Key_ID", metaSig), metaPayload);

        // --- Vehicle / ECU side ---
        // Verify blob signature
        start = System.nanoTime();
        profile.signer().verify(blob.signedPayload(), blob.signature().signatureBytes(),
                oemKey.getPublic());
        t[idx++] = System.nanoTime() - start;

        // Verify metadata signature
        start = System.nanoTime();
        profile.signer().verify(metadata.signedPayload(), metadata.signature().signatureBytes(),
                directorKey.getPublic());
        t[idx++] = System.nanoTime() - start;

        // Unwrap session key
        start = System.nanoTime();
        byte[] recoveredKey = profile.keyWrapper().unwrap(wrappedKey, ecuKey.getPrivate());
        t[idx++] = System.nanoTime() - start;

        // Decrypt payload
        byte[] ctWithTag = Util.concat(blob.ciphertext().payload(),
                blob.ciphertext().authenticationTag());
        start = System.nanoTime();
        byte[] decrypted = profile.encryptor().decrypt(recoveredKey, blob.ciphertext().nonce(),
                ctWithTag, aad);
        t[idx++] = System.nanoTime() - start;

        // Hash check
        start = System.nanoTime();
        profile.hasher().hash(decrypted);
        t[idx++] = System.nanoTime() - start;

        return new TimedRun(t, blob);
    }

    private byte[] buildMetaPayload(java.time.Instant expires, TargetFile target) {
        String s = "expires:" + expires
                + "|" + target.filename() + ":" + target.length()
                + ":" + target.sha256() + ":" + target.version()
                + ":" + String.join(",", target.hardwareIds());
        return s.getBytes();
    }

    private long median(long[] sorted) {
        int n = sorted.length;
        if (n % 2 == 0) {
            return (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
        }
        return sorted[n / 2];
    }
}
