import java.io.*;
import java.util.*;

public class Main {

    // ── App Classification ─────────────────────────────────────────
    // Maps SNI domain keywords to AppType
    // Called after SNI is extracted

    static AppType classifyFromSni(String sni) {
    if (sni == null) return AppType.UNKNOWN;
    String s = sni.toLowerCase();

    if (s.contains("youtube") || s.contains("googlevideo")) return AppType.YOUTUBE;
    if (s.contains("facebook") || s.contains("fbcdn"))      return AppType.FACEBOOK;
    if (s.contains("netflix"))                               return AppType.NETFLIX;
    if (s.contains("tiktok") || s.contains("tiktokcdn"))    return AppType.TIKTOK;
    if (s.contains("twitter") || s.contains("twimg"))       return AppType.TWITTER;
    if (s.contains("instagram"))                             return AppType.INSTAGRAM;
    if (s.contains("whatsapp"))                              return AppType.WHATSAPP;
    if (s.contains("github"))                                return AppType.GITHUB;
    if (s.contains("discord"))                               return AppType.DISCORD;
    if (s.contains("zoom"))                                  return AppType.ZOOM;
    if (s.contains("telegram"))                              return AppType.TELEGRAM;
    if (s.contains("spotify"))                               return AppType.SPOTIFY;
    if (s.contains("amazon") || s.contains("amazonaws"))    return AppType.AMAZON;
    if (s.contains("microsoft") || s.contains("bing"))      return AppType.MICROSOFT;
    if (s.contains("apple") || s.contains("icloud"))        return AppType.APPLE;
    if (s.contains("cloudflare"))                            return AppType.CLOUDFLARE;
    if (s.contains("google"))                                return AppType.GOOGLE;  // keep last, broad match

    return AppType.UNKNOWN;
}

    // ── Port-based classification (fallback when no SNI) ──────────

    static AppType classifyFromPort(ParsedPacket pkt) {
        int port = pkt.dstPort;
        if (port == 53)                    return AppType.DNS;
        if (port == 80)                    return AppType.HTTP;
        if (port == 443)                   return AppType.HTTPS;
        return AppType.UNKNOWN;
    }

    // ── Write PCAP Global Header ───────────────────────────────────
    // Must be written once at the start of every output PCAP file

    static void writePcapGlobalHeader(OutputStream out) throws IOException {
        // Magic number (little-endian)
        // Version 2.4, link type 1 (Ethernet)
        byte[] header = new byte[] {
            (byte)0xD4, (byte)0xC3, (byte)0xB2, (byte)0xA1, // magic (little-endian)
            0x02, 0x00,                                        // major version = 2
            0x04, 0x00,                                        // minor version = 4
            0x00, 0x00, 0x00, 0x00,                           // GMT offset = 0
            0x00, 0x00, 0x00, 0x00,                           // timestamp accuracy = 0
            (byte)0xFF, (byte)0xFF, 0x00, 0x00,               // snapshot length = 65535
            0x01, 0x00, 0x00, 0x00                            // link type = 1 (Ethernet)
        };
        out.write(header);
    }

    // ── Write single packet to output PCAP ────────────────────────
    // Each packet = 16-byte header + raw data bytes

    static void writePacket(OutputStream out, ParsedPacket pkt) throws IOException {
        byte[] hdr = new byte[16];
        int len = pkt.rawData.length;

        // Timestamp seconds (little-endian)
        hdr[0] = (byte)(pkt.timestampSec);
        hdr[1] = (byte)(pkt.timestampSec >> 8);
        hdr[2] = (byte)(pkt.timestampSec >> 16);
        hdr[3] = (byte)(pkt.timestampSec >> 24);

        // Timestamp microseconds (little-endian)
        hdr[4] = (byte)(pkt.timestampUsec);
        hdr[5] = (byte)(pkt.timestampUsec >> 8);
        hdr[6] = (byte)(pkt.timestampUsec >> 16);
        hdr[7] = (byte)(pkt.timestampUsec >> 24);

        // Captured length (little-endian)
        hdr[8]  = (byte)(len);
        hdr[9]  = (byte)(len >> 8);
        hdr[10] = (byte)(len >> 16);
        hdr[11] = (byte)(len >> 24);

        // Original length (same as captured for our purposes)
        hdr[12] = (byte)(len);
        hdr[13] = (byte)(len >> 8);
        hdr[14] = (byte)(len >> 16);
        hdr[15] = (byte)(len >> 24);

        out.write(hdr);
        out.write(pkt.rawData);
    }

    // ── Main ───────────────────────────────────────────────────────

    public static void main(String[] args) throws IOException {

        // ── Parse command-line args ────────────────────────────────
        if (args.length < 2) {
            System.out.println("Usage: java Main <input.pcap> <output.pcap> [options]");
            System.out.println("Options:");
            System.out.println("  --block-ip <ip>        Block a source IP");
            System.out.println("  --block-app <app>      Block an app (YOUTUBE, NETFLIX ...)");
            System.out.println("  --block-domain <name>  Block a domain keyword");
            return;
        }

        String inputFile  = args[0];
        String outputFile = args[1];

        RuleManager rules = new RuleManager();

        // Parse optional blocking flags
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip":
                    if (i + 1 < args.length) rules.blockIp(args[++i]);
                    break;
                case "--block-app":
                    if (i + 1 < args.length) {
                        try {
                            rules.blockApp(AppType.valueOf(args[++i].toUpperCase()));
                        } catch (IllegalArgumentException e) {
                            System.out.println("[Warn] Unknown app type: " + args[i]);
                        }
                    }
                    break;
                case "--block-domain":
                    if (i + 1 < args.length) rules.blockDomain(args[++i]);
                    break;
                default:
                    System.out.println("[Warn] Unknown option: " + args[i]);
            }
        }

        // ── Setup ──────────────────────────────────────────────────
        PcapReader    reader  = new PcapReader();
        FlowTracker   tracker = new FlowTracker();
        FileOutputStream fos  = new FileOutputStream(outputFile);
        BufferedOutputStream out = new BufferedOutputStream(fos);

        // Stats counters
        int totalPackets = 0;
        int tcpPackets   = 0;
        int udpPackets   = 0;
        int forwarded    = 0;
        int dropped      = 0;

        Map<AppType, Integer> appCounts   = new LinkedHashMap<>();
        Map<String,  String>  sniAppMap   = new LinkedHashMap<>(); // domain → app name

        for (AppType a : AppType.values()) appCounts.put(a, 0);

        // ── Open files ────────────────────────────────────────────
        reader.open(inputFile);
        writePcapGlobalHeader(out);

        System.out.println("\n╔══════════════════════════════════════════╗");
        System.out.println("║       DPI ENGINE - Simple Java Version   ║");
        System.out.println("╚══════════════════════════════════════════╝\n");

        // ── Main processing loop ───────────────────────────────────
        ParsedPacket pkt = new ParsedPacket();

        while (reader.readNextPacket(pkt)) {
            totalPackets++;

            // Step 1: Parse Ethernet/IP/TCP/UDP headers
            PacketParser.parse(pkt);

            if (pkt.isTcp) tcpPackets++;
            if (pkt.isUdp) udpPackets++;

            // Step 2: Build five-tuple and check flow table
            FiveTuple tuple = pkt.toFiveTuple();
            FlowState  flow  = tracker.getOrCreate(tuple);

            // Step 3: If flow already blocked → drop immediately
            if (flow.blocked) {
                dropped++;
                pkt = new ParsedPacket(); // reset for next packet
                continue;
            }

            // Step 4: If SNI not yet seen for this flow → try to extract
            if (!flow.sniSeen && pkt.isTcp && pkt.payload != null
                                           && pkt.payload.length > 0) {

                // Try TLS SNI first
                String sni = SniExtractor.extractSni(pkt.payload);

                // Fallback: try HTTP Host header
                if (sni == null) sni = SniExtractor.extractHttpHost(pkt.payload);

                if (sni != null) {
                    AppType app = classifyFromSni(sni);
                    pkt.sni     = sni;
                    pkt.appType = app;
                    tracker.updateFlow(tuple, sni, app);
                    sniAppMap.put(sni, app.toString());
                } else {
                    // Port-based fallback classification
                    pkt.appType = classifyFromPort(pkt);
                    flow.appType = pkt.appType;
                }

            } else if (flow.sniSeen) {
                // Carry forward what we already know about this flow
                pkt.sni     = flow.sni;
                pkt.appType = flow.appType;
            } else {
                pkt.appType = classifyFromPort(pkt);
            }

            // Step 5: Check blocking rules
            boolean block = rules.shouldBlock(pkt);
            if (!block && flow.sniSeen) block = rules.shouldBlockFlow(flow);

            if (block) {
                flow.blocked = true;
                pkt.blocked  = true;
                dropped++;
            } else {
                // Step 6: Forward — write to output PCAP
                writePacket(out, pkt);
                forwarded++;
            }

            // Step 7: Update app stats
            if (pkt.appType != null) {
            appCounts.merge(pkt.appType, 1, Integer::sum);
                }

            // Reset for next iteration
            pkt = new ParsedPacket();
        }

        // ── Cleanup ────────────────────────────────────────────────
        out.flush();
        out.close();
        reader.close();

        // ── Print Report ───────────────────────────────────────────
        System.out.println("==========================================");
        System.out.println("       DPI ENGINE - Simple Java Version   ");
        System.out.println("==========================================");

        // and for the report:
        System.out.println("==========================================");
        System.out.println("             PROCESSING REPORT            ");
        System.out.println("==========================================");
        System.out.printf( "  Total Packets  : %d%n", totalPackets);
        System.out.printf( "  TCP Packets    : %d%n", tcpPackets);
        System.out.printf( "  UDP Packets    : %d%n", udpPackets);
        System.out.println("------------------------------------------");
        System.out.printf( "  Forwarded      : %d%n", forwarded);
        System.out.printf( "  Dropped        : %d%n", dropped);
        System.out.println("------------------------------------------");
        System.out.println("  APPLICATION BREAKDOWN");
        System.out.println("------------------------------------------");
        // ... rest of the report
        appCounts.entrySet().stream()
            .filter(e -> e.getValue() > 0)
            .sorted((a, b) -> b.getValue() - a.getValue())
            .forEach(e -> {
                String blocked = rules.getBlockedApps().contains(e.getKey())
                                 ? " (BLOCKED)" : "";
                System.out.printf("  %-14s : %-22s %n",
                    e.getKey() + blocked, e.getValue());
            });

        System.out.println("------------------------------------------");
        System.out.println("  DETECTED DOMAINS / SNIs");
        System.out.println("------------------------------------------");

        if (sniAppMap.isEmpty()) {
            System.out.println("  (none detected)");
        } else {
            sniAppMap.forEach((sni, app) ->
                System.out.printf("  %-30s -> %s%n", sni, app));
        }

        System.out.println("==========================================");

        tracker.printSummary();
        System.out.println("\n[Done] Output written to: " + outputFile);
    }
}