package uptane.benchmark;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Collected timing and size measurements for a single crypto profile run.
 * All times are in nanoseconds; use {@link #toMicros} for display.
 */
public class BenchmarkResult {

    private final String profileName;
    private final Map<String, Long> timings = new LinkedHashMap<>();
    private final Map<String, Integer> sizes = new LinkedHashMap<>();

    public BenchmarkResult(String profileName) {
        this.profileName = profileName;
    }

    public String profileName() { return profileName; }
    public Map<String, Long> timings() { return timings; }
    public Map<String, Integer> sizes() { return sizes; }

    public void recordTimeNanos(String metric, long nanos) {
        timings.put(metric, nanos);
    }

    public void recordSize(String metric, int bytes) {
        sizes.put(metric, bytes);
    }

    public static long toMicros(long nanos) {
        return nanos / 1_000;
    }
}
