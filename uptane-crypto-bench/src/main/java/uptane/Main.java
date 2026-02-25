package uptane;

import uptane.benchmark.BenchmarkResult;
import uptane.benchmark.BenchmarkRunner;
import uptane.benchmark.ResultPrinter;
import uptane.crypto.CryptoProfile;
import uptane.crypto.Profiles;
import uptane.director.DirectorService;
import uptane.model.*;
import uptane.oem.OemPackager;
import uptane.oem.OemPackager.RecipientEntry;
import uptane.vehicle.VehicleEcu;
import uptane.vehicle.VehicleEcu.InstallResult;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Entry point for the Uptane cryptographic case study.
 *
 * Runs two phases:
 * 1. Smoke test — verifies the full OEM → Director → Vehicle flow works for each profile
 * 2. Benchmark — measures timing and sizes across all profiles
 */
public class Main {

    private static final int BENCHMARK_ITERATIONS = 100;

    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("  UPTANE CRYPTOGRAPHIC CASE STUDY");
        System.out.println("=".repeat(60));

        // Build the shared firmware image (same for all profiles)
        UpdateFirmware firmware = Util.defaultFirmware();
        System.out.println("\nFirmware: " + firmware.filename()
                + " v" + firmware.version()
                + " (" + firmware.length() + " bytes)");
        System.out.println("SHA-256:  " + firmware.sha256());

        VehicleContext vehicle = new VehicleContext("VIN_5566_HASH", "ECU_Type_A", 1);

        // Phase 1: Smoke test each profile
        System.out.println("\n--- Smoke Test ---");
        for (CryptoProfile profile : Profiles.all()) {
            smokeTest(profile, firmware, vehicle);
        }

        // Phase 2: Benchmark
        System.out.println("\n--- Benchmark ---");
        int iterations = BENCHMARK_ITERATIONS;
        if (args.length > 0) {
            try {
                iterations = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {}
        }

        BenchmarkRunner runner = new BenchmarkRunner(iterations);
        List<BenchmarkResult> results = new ArrayList<>();

        for (CryptoProfile profile : Profiles.all()) {
            System.out.println("Benchmarking " + profile.name() + "...");
            results.add(runner.run(profile, firmware));
        }

        ResultPrinter.printTable(results, iterations);
    }

    /**
     * Run the full Uptane flow for one profile and verify correctness.
     */
    private static void smokeTest(CryptoProfile profile, UpdateFirmware firmware,
                                  VehicleContext vehicle) {
        System.out.print(profile.name() + " ... ");

        // Generate keys for all three roles
        KeyPair oemKey = profile.signer().generateKeyPair();
        KeyPair directorKey = profile.signer().generateKeyPair();
        KeyPair ecuKey = profile.keyWrapper().generateRecipientKeyPair();

        // OEM packages the firmware
        OemPackager oem = new OemPackager(profile, oemKey);
        UpdateBlob blob = oem.packageFirmware(firmware,
                List.of(new RecipientEntry(vehicle.recipientId(), ecuKey.getPublic())));

        // Director signs the metadata
        DirectorService director = new DirectorService(profile, directorKey);
        TargetsMetadata metadata = director.buildTargetsMetadata(firmware);

        // Vehicle verifies and decrypts
        VehicleEcu ecu = new VehicleEcu(profile, ecuKey,
                oemKey.getPublic(), directorKey.getPublic());
        InstallResult result = ecu.processUpdate(blob, metadata, vehicle);

        if (result.accepted() && Arrays.equals(result.firmware(), firmware.payload())) {
            System.out.println("OK (decrypted payload matches original)");
        } else {
            System.out.println("FAILED: " + result.reason());
        }
    }
}
