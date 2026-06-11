import java.util.HashMap;
import java.util.Map;

public class FlowTracker {

    private final Map<FiveTuple, FlowState> table = new HashMap<>();

    // Get existing flow state, or create a new one
    public FlowState getOrCreate(FiveTuple key) {
        return table.computeIfAbsent(key, k -> new FlowState());
    }

    // Update flow once we've identified the app/SNI
    public void updateFlow(FiveTuple key, String sni, AppType appType) {
        FlowState flow = getOrCreate(key);
        if (!flow.sniSeen) {          // only update once
            flow.sni     = sni;
            flow.appType = appType;
            flow.sniSeen = true;
        }
    }

    // Mark a flow as blocked — all future packets will be dropped
    public void markBlocked(FiveTuple key) {
        FlowState flow = getOrCreate(key);
        flow.blocked = true;
    }

    // Direct lookup — returns null if flow doesn't exist yet
    public FlowState get(FiveTuple key) {
        return table.get(key);
    }

    public int flowCount() {
        return table.size();
    }

    // ── Stats ─────────────────────────────────────────────────────

    public void printSummary() {
        System.out.println("\n[Flow Table] Total flows tracked: " + table.size());
        int blocked = 0;
        int identified = 0;
        for (FlowState f : table.values()) {
            if (f.blocked)            blocked++;
            if (f.appType != AppType.UNKNOWN) identified++;
        }
        System.out.println("[Flow Table] Identified: " + identified +
                           "  Blocked: " + blocked);
    }
}