import java.io.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class DpiEngine {

    // ── Config ────────────────────────────────────────────────────
    static final int NUM_LBS = 2;   // number of Load Balancer threads
    static final int NUM_FPS = 4;   // number of Fast Path threads (per LB queue group)

    // ── Classification (shared, read-only — safe across threads) ──

    public static AppType classifyFromSni(String sni) {
        if (sni == null) return AppType.UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("googlevideo")) return AppType.YOUTUBE;
        if (s.contains("facebook") || s.contains("fbcdn"))      return AppType.FACEBOOK;
        if (s.contains("netflix"))                               return AppType.NETFLIX;
        if (s.contains("tiktok"))                                return AppType.TIKTOK;
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
        if (s.contains("google"))                                return AppType.GOOGLE;
        return AppType.UNKNOWN;
    }

    public static AppType classifyFromPort(ParsedPacket pkt) {
        if (pkt.dstPort == 53)  return AppType.DNS;
        if (pkt.dstPort == 80)  return AppType.HTTP;
        if (pkt.dstPort == 443) return AppType.HTTPS;
        return AppType.UNKNOWN;
    }

    // ── Main ──────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {

        if (args.length < 2) {
            System.out.println("Usage: java DpiEngine <input.pcap> <output.pcap> [options]");
            System.out.println("Options:");
            System.out.println("  --block-ip <ip>");
            System.out.println("  --block-app <app>");
            System.out.println("  --block-domain <domain>");
            System.out.println("  --lbs <N>   (default: 2)");
            System.out.println("  --fps <N>   (default: 4)");
            return;
        }

        String inputFile  = args[0];
        String outputFile = args[1];

        // Parse options
        int numLbs = NUM_LBS;
        int numFps = NUM_FPS;
        RuleManager rules = new RuleManager();
        Main.loadRulesFromFile("..\\rules.txt", rules);

        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip":
                    if (i+1 < args.length) rules.blockIp(args[++i]);     break;
                case "--block-app":
                    if (i+1 < args.length) {
                        try { rules.blockApp(AppType.valueOf(args[++i].toUpperCase())); }
                        catch (IllegalArgumentException e) {
                            System.out.println("[Warn] Unknown app: " + args[i]); }
                    } break;
                case "--block-domain":
                    if (i+1 < args.length) rules.blockDomain(args[++i]); break;
                case "--lbs":
                    if (i+1 < args.length) numLbs = Integer.parseInt(args[++i]); break;
                case "--fps":
                    if (i+1 < args.length) numFps = Integer.parseInt(args[++i]); break;
            }
        }

        System.out.println("\n==========================================");
        System.out.println("   DPI ENGINE - Multi-threaded Java");
        System.out.printf ("   Load Balancers : %d%n", numLbs);
        System.out.printf ("   Fast Paths     : %d%n", numFps);
        System.out.println("==========================================\n");

        // ── Shared counters ───────────────────────────────────────
        AtomicInteger totalPackets    = new AtomicInteger(0);
        AtomicInteger droppedPackets  = new AtomicInteger(0);
        AtomicInteger forwardedPackets= new AtomicInteger(0);

        // ── Output queue (FPs → Writer) ───────────────────────────
        BlockingQueue<ParsedPacket> outputQueue = new LinkedBlockingQueue<>(2000);

        // ── Create FP input queues ────────────────────────────────
        BlockingQueue<RawPacket>[] fpQueues = new LinkedBlockingQueue[numFps];
        for (int i = 0; i < numFps; i++) {
            fpQueues[i] = new LinkedBlockingQueue<>(1000);
        }

        // ── Create and start Fast Path threads ────────────────────
        Thread[] fpThreads = new Thread[numFps];
        for (int i = 0; i < numFps; i++) {
            FastPath fp = new FastPath(i, fpQueues[i], outputQueue, rules,
                                       totalPackets, droppedPackets, forwardedPackets);
            fpThreads[i] = new Thread(fp, "FastPath-" + i);
            fpThreads[i].start();
        }

        // ── Create and start Load Balancer threads ─────────────────
        // Split FP queues evenly across LBs
        Thread[] lbThreads = new Thread[numLbs];
        LoadBalancer[] lbs = new LoadBalancer[numLbs];

        int fpsPerLb = numFps / numLbs;
        for (int i = 0; i < numLbs; i++) {
            // Each LB gets a slice of the FP queues
            int start = i * fpsPerLb;
            int end   = (i == numLbs - 1) ? numFps : start + fpsPerLb;
            int count = end - start;

            BlockingQueue<RawPacket>[] lbFpQueues = new LinkedBlockingQueue[count];
            for (int j = 0; j < count; j++) lbFpQueues[j] = fpQueues[start + j];

            lbs[i] = new LoadBalancer(i, lbFpQueues);
            lbThreads[i] = new Thread(lbs[i], "LoadBalancer-" + i);
            lbThreads[i].start();
        }

        // ── Create and start Writer thread ─────────────────────────
        WriterThread writer = new WriterThread(outputQueue, outputFile, numFps,
                                               totalPackets, droppedPackets,
                                               forwardedPackets, rules);
        Thread writerThread = new Thread(writer, "Writer");
        writerThread.start();

        // ── Reader: main thread reads PCAP, feeds LB queues ───────
        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        ParsedPacket tmp = new ParsedPacket();
        int pktCount = 0;

        while (reader.readNextPacket(tmp)) {
            RawPacket raw = new RawPacket(
                tmp.rawData.clone(),
                tmp.timestampSec,
                tmp.timestampUsec
            );

            // Select LB by simple round-robin (LB does the real hashing)
            int lbIdx = pktCount % numLbs;
            lbs[lbIdx].getInputQueue().put(raw);

            pktCount++;
            tmp = new ParsedPacket();
        }

        reader.close();
        System.out.println("[Reader] Done. Sent " + pktCount + " packets.");

        // ── Shutdown: send one poison pill per LB ─────────────────
        for (int i = 0; i < numLbs; i++) {
            lbs[i].getInputQueue().put(RawPacket.poisonPill());
        }

        // ── Wait for all threads to finish ────────────────────────
        for (Thread t : lbThreads)  t.join();
        for (Thread t : fpThreads)  t.join();
        writerThread.join();

        System.out.println("\n[DpiEngine] All threads stopped.");
    }
}