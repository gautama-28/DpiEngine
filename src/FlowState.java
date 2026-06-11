public class FlowState {
    public AppType appType = AppType.UNKNOWN;
    public String sni = null;
    public boolean blocked = false;
    public boolean sniSeen = false; // have we already extracted SNI for this flow?

    public FlowState() {}
}