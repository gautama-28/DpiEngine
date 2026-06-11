public class ParsedPacket {
    // Raw bytes (needed to write to output PCAP)
    public byte[] rawData;
    public long timestampSec;
    public long timestampUsec;

    // Ethernet
    public String srcMac;
    public String dstMac;
    public int etherType; // 0x0800 = IPv4

    // IP
    public String srcIp;
    public String dstIp;
    public int protocol; // 6=TCP, 17=UDP
    public int ipHeaderLen;

    // TCP/UDP
    public int srcPort;
    public int dstPort;
    public int tcpHeaderLen;
    public boolean isTcp;
    public boolean isUdp;

    // Payload
    public byte[] payload;
    public int payloadOffset; // offset into rawData

    // After classification
    public String sni;          // extracted domain (e.g. "www.youtube.com")
    public AppType appType = AppType.UNKNOWN;
    public boolean blocked = false;

    public FiveTuple toFiveTuple() {
        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
    }
}