import java.util.HashSet;
import java.util.Set;

public class RuleManager {

    private final Set<String> blockedIps     = new HashSet<>();
    private final Set<AppType> blockedApps   = new HashSet<>();
    private final Set<String> blockedDomains = new HashSet<>();

    // ── Add Rules ─────────────────────────────────────────────────

    public void blockIp(String ip) {
        blockedIps.add(ip);
        System.out.println("[Rules] Blocking IP: " + ip);
    }

    public void blockApp(AppType app) {
        blockedApps.add(app);
        System.out.println("[Rules] Blocking App: " + app);
    }

    public void blockDomain(String domain) {
        // Store lowercase so matching is case-insensitive
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocking Domain: " + domain);
    }

    // ── Main Check ────────────────────────────────────────────────

    // Returns true if this packet should be dropped
    public boolean shouldBlock(ParsedPacket pkt) {

        // 1. Check source IP
        if (blockedIps.contains(pkt.srcIp)) return true;

        // 2. Check app type
        if (pkt.appType != AppType.UNKNOWN && blockedApps.contains(pkt.appType))
            return true;

        // 3. Check SNI / domain substring match
        //    e.g. blocking "youtube" will match "www.youtube.com"
        if (pkt.sni != null) {
            String sniLower = pkt.sni.toLowerCase();
            for (String blocked : blockedDomains) {
                if (sniLower.contains(blocked)) return true;
            }
        }

        return false;
    }

    // ── Also check by FlowState ───────────────────────────────────
    // Used when we already know the flow is identified
    // but the current packet has no SNI (subsequent packets)

    public boolean shouldBlockFlow(FlowState flow) {
        if (flow == null) return false;
        if (blockedApps.contains(flow.appType)) return true;
        if (flow.sni != null) {
            String sniLower = flow.sni.toLowerCase();
            for (String blocked : blockedDomains) {
                if (sniLower.contains(blocked)) return true;
            }
        }
        return false;
    }

    // ── Getters (useful for printing summary) ─────────────────────

    public Set<String>   getBlockedIps()     { return blockedIps; }
    public Set<AppType>  getBlockedApps()    { return blockedApps; }
    public Set<String>   getBlockedDomains() { return blockedDomains; }

    public boolean hasRules() {
        return !blockedIps.isEmpty() ||
               !blockedApps.isEmpty() ||
               !blockedDomains.isEmpty();
    }
}