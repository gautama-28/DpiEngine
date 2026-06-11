public class PacketParser {

    // Ethernet header is always exactly 14 bytes
    private static final int ETH_HEADER_LEN = 14;

    public static void parse(ParsedPacket pkt) {
        byte[] data = pkt.rawData;

        if (data.length < ETH_HEADER_LEN) return; // too small, skip

        // ── LAYER 2: Ethernet ─────────────────────────────────────
        //
        // Byte layout:
        // [0-5]   Destination MAC
        // [6-11]  Source MAC
        // [12-13] EtherType (0x0800 = IPv4, 0x86DD = IPv6)

        pkt.dstMac = parseMac(data, 0);
        pkt.srcMac = parseMac(data, 6);
        pkt.etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);

        // We only handle IPv4 for now
        if (pkt.etherType != 0x0800) return;

        // ── LAYER 3: IP ───────────────────────────────────────────
        //
        // IP header starts right after Ethernet (offset 14)
        //
        // Byte layout (offsets from start of IP header):
        // [0]     Version (upper 4 bits) + IHL (lower 4 bits)
        // [1]     DSCP/ECN (ignore)
        // [2-3]   Total length
        // [4-5]   Identification (ignore)
        // [6-7]   Flags + Fragment offset (ignore)
        // [8]     TTL (ignore)
        // [9]     Protocol (6=TCP, 17=UDP)
        // [10-11] Header checksum (ignore)
        // [12-15] Source IP
        // [16-19] Destination IP

        int ipOffset = ETH_HEADER_LEN; // = 14

        if (data.length < ipOffset + 20) return; // need at least 20 bytes for IP

        // IHL = lower 4 bits of first byte, value is in units of 4 bytes
        // e.g. IHL=5 means 5*4 = 20 bytes (standard, no options)
        //      IHL=6 means 6*4 = 24 bytes (with options)
        int ihl = (data[ipOffset] & 0x0F);
        pkt.ipHeaderLen = ihl * 4;

        pkt.protocol = data[ipOffset + 9] & 0xFF; // 6=TCP, 17=UDP

        pkt.srcIp = parseIp(data, ipOffset + 12);
        pkt.dstIp = parseIp(data, ipOffset + 16);

        // ── LAYER 4: TCP or UDP ───────────────────────────────────
        //
        // Transport header starts right after IP header
        int transportOffset = ipOffset + pkt.ipHeaderLen;

        if (pkt.protocol == 6) {
            parseTcp(pkt, data, transportOffset);
        } else if (pkt.protocol == 17) {
            parseUdp(pkt, data, transportOffset);
        }
    }

    // ── TCP ───────────────────────────────────────────────────────
    //
    // TCP header layout (offsets from start of TCP header):
    // [0-1]   Source port
    // [2-3]   Destination port
    // [4-7]   Sequence number (ignore)
    // [8-11]  Acknowledgment number (ignore)
    // [12]    Data offset (upper 4 bits) — header length in 4-byte units
    // [13]    Flags (SYN, ACK, FIN, RST etc.) (ignore for now)
    // [14-15] Window size (ignore)
    // [16-17] Checksum (ignore)
    // [18-19] Urgent pointer (ignore)
    // [20+]   Options (if data offset > 5)
    // [dataOffset*4 +] Payload

    private static void parseTcp(ParsedPacket pkt, byte[] data, int offset) {
        if (data.length < offset + 20) return;

        pkt.isTcp = true;
        pkt.srcPort = readShort(data, offset);
        pkt.dstPort = readShort(data, offset + 2);

        // Data offset: upper 4 bits of byte 12, in units of 4 bytes
        int dataOffset = (data[offset + 12] & 0xF0) >> 4;
        pkt.tcpHeaderLen = dataOffset * 4;

        // Payload starts after TCP header
        pkt.payloadOffset = offset + pkt.tcpHeaderLen;

        if (pkt.payloadOffset < data.length) {
            int payloadLen = data.length - pkt.payloadOffset;
            pkt.payload = new byte[payloadLen];
            System.arraycopy(data, pkt.payloadOffset, pkt.payload, 0, payloadLen);
        } else {
            pkt.payload = new byte[0];
        }
    }

    // ── UDP ───────────────────────────────────────────────────────
    //
    // UDP header layout (8 bytes, always fixed):
    // [0-1] Source port
    // [2-3] Destination port
    // [4-5] Length
    // [6-7] Checksum (ignore)

    private static void parseUdp(ParsedPacket pkt, byte[] data, int offset) {
        if (data.length < offset + 8) return;

        pkt.isUdp = true;
        pkt.srcPort = readShort(data, offset);
        pkt.dstPort = readShort(data, offset + 2);

        pkt.payloadOffset = offset + 8;

        if (pkt.payloadOffset < data.length) {
            int payloadLen = data.length - pkt.payloadOffset;
            pkt.payload = new byte[payloadLen];
            System.arraycopy(data, pkt.payloadOffset, pkt.payload, 0, payloadLen);
        } else {
            pkt.payload = new byte[0];
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    // MAC address: 6 bytes formatted as "AA:BB:CC:DD:EE:FF"
    private static String parseMac(byte[] data, int offset) {
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
            data[offset]   & 0xFF, data[offset+1] & 0xFF,
            data[offset+2] & 0xFF, data[offset+3] & 0xFF,
            data[offset+4] & 0xFF, data[offset+5] & 0xFF);
    }

    // IP address: 4 bytes formatted as "192.168.1.1"
    private static String parseIp(byte[] data, int offset) {
        return (data[offset]   & 0xFF) + "." +
               (data[offset+1] & 0xFF) + "." +
               (data[offset+2] & 0xFF) + "." +
               (data[offset+3] & 0xFF);
    }

    // Read 2 bytes as unsigned int (port numbers)
    private static int readShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset+1] & 0xFF);
    }
}