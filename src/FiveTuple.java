import java.util.Objects;

public class FiveTuple {
    public final String srcIp;
    public final String dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol;

    public FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, int protocol) {
        // Normalize so both directions map to the same key
        // Compare by IP first, then port if IPs are equal
        boolean flip = srcIp.compareTo(dstIp) > 0 ||
                       (srcIp.equals(dstIp) && srcPort > dstPort);

        if (flip) {
            this.srcIp   = dstIp;
            this.dstIp   = srcIp;
            this.srcPort = dstPort;
            this.dstPort = srcPort;
        } else {
            this.srcIp   = srcIp;
            this.dstIp   = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
        }
        this.protocol = protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcPort == t.srcPort && dstPort == t.dstPort &&
               protocol == t.protocol &&
               srcIp.equals(t.srcIp) && dstIp.equals(t.dstIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort +
               " [" + (protocol == 6 ? "TCP" : "UDP") + "]";
    }
}