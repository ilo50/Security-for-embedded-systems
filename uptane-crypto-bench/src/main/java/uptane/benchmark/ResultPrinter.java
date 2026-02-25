package uptane.benchmark;

import java.util.List;
import java.util.Map;

/**
 * Prints benchmark results as a formatted comparison table.
 */
public final class ResultPrinter {

    private ResultPrinter() {}

    /**
     * Print a comparison table of all profile results to stdout.
     */
    public static void printTable(List<BenchmarkResult> results, int iterations) {
        System.out.println();
        System.out.println("=".repeat(120));
        System.out.println("  UPTANE CRYPTOGRAPHIC PROFILE COMPARISON");
        System.out.println("  (" + iterations + " iterations, median values)");
        System.out.println("=".repeat(120));
        System.out.println();

        // Timing table
        String[] timeMetrics = {
                "OEM Encrypt", "OEM KeyWrap", "OEM Sign",
                "Dir Hash", "Dir Sign",
                "ECU VerifyBlob", "ECU VerifyMeta", "ECU Unwrap", "ECU Decrypt", "ECU HashCheck"
        };

        // Header
        System.out.printf("%-18s", "Profile");
        for (String m : timeMetrics) {
            System.out.printf(" | %14s", m + " (us)");
        }
        System.out.println();
        System.out.println("-".repeat(18) + ("-+-" + "-".repeat(14)).repeat(timeMetrics.length));

        // Rows
        for (BenchmarkResult r : results) {
            System.out.printf("%-18s", r.profileName());
            for (String m : timeMetrics) {
                Long nanos = r.timings().get(m);
                long micros = nanos != null ? BenchmarkResult.toMicros(nanos) : -1;
                System.out.printf(" | %14d", micros);
            }
            System.out.println();
        }

        System.out.println();

        // Size table
        String[] sizeMetrics = {"Signature", "Ciphertext", "WrappedKey"};

        System.out.printf("%-18s", "Profile");
        for (String m : sizeMetrics) {
            System.out.printf(" | %14s", m + " (B)");
        }
        System.out.println();
        System.out.println("-".repeat(18) + ("-+-" + "-".repeat(14)).repeat(sizeMetrics.length));

        for (BenchmarkResult r : results) {
            System.out.printf("%-18s", r.profileName());
            for (String m : sizeMetrics) {
                Integer bytes = r.sizes().get(m);
                System.out.printf(" | %14d", bytes != null ? bytes : -1);
            }
            System.out.println();
        }

        System.out.println();

        // CSV output for easy import
        System.out.println("--- CSV (for spreadsheet import) ---");
        System.out.print("Profile");
        for (String m : timeMetrics) System.out.print("," + m + " (us)");
        for (String m : sizeMetrics) System.out.print("," + m + " (B)");
        System.out.println();

        for (BenchmarkResult r : results) {
            System.out.print(r.profileName());
            for (String m : timeMetrics) {
                Long nanos = r.timings().get(m);
                System.out.print("," + (nanos != null ? BenchmarkResult.toMicros(nanos) : -1));
            }
            for (String m : sizeMetrics) {
                Integer bytes = r.sizes().get(m);
                System.out.print("," + (bytes != null ? bytes : -1));
            }
            System.out.println();
        }
    }
}
