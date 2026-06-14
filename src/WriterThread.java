import java.io.*;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class WriterThread implements Runnable {

    private final BlockingQueue<ParsedPacket> outputQueue;
    private final String                      outputFile;
    private final int                         numFPs;      // how many poison pills to expect
    private final AtomicInteger               totalPackets;
    private final AtomicInteger               dropped;
    private final AtomicInteger               forwarded;
    private final RuleManager                 rules;

    // Stats collected by writer
    private final Map<AppType, Integer> appCounts  = new LinkedHashMap<>();
    private final Map<String, String>   sniAppMap  = new LinkedHashMap<>();

    public WriterThread(BlockingQueue<ParsedPacket> outputQueue,
                        String                      outputFile,
                        int                         numFPs,
                        AtomicInteger               totalPackets,
                        AtomicInteger               dropped,
                        AtomicInteger               forwarded,
                        RuleManager                 rules) {
        this.outputQueue  = outputQueue;
        this.outputFile   = outputFile;
        this.numFPs       = numFPs;
        this.totalPackets = totalPackets;
        this.dropped      = dropped;
        this.forwarded    = forwarded;
        this.rules        = rules;

        for (AppType a : AppType.values()) appCounts.put(a, 0);
    }

    @Override
    public void run() {
        System.out.println("[Writer] Started");

        try (BufferedOutputStream out =
                new BufferedOutputStream(new FileOutputStream(outputFile))) {

            Main.writePcapGlobalHeader(out);

            int poisonPillsReceived = 0;

            while (poisonPillsReceived < numFPs) {
                ParsedPacket pkt = outputQueue.take();

                // Detect poison pill (rawData == null)
                if (pkt.rawData == null) {
                    poisonPillsReceived++;
                    System.out.println("[Writer] FP done signal " +
                                       poisonPillsReceived + "/" + numFPs);
                    continue;
                }

                // Write packet to output PCAP
                Main.writePacket(out, pkt);

                // Collect stats
                if (pkt.appType != null) {
                    appCounts.merge(pkt.appType, 1, Integer::sum);
                }
                if (pkt.sni != null && !sniAppMap.containsKey(pkt.sni)) {
                    sniAppMap.put(pkt.sni, pkt.appType != null ?
                                           pkt.appType.toString() : "UNKNOWN");
                }
            }

            out.flush();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException e) {
            System.err.println("[Writer] IO error: " + e.getMessage());
        }

        printReport();
        System.out.println("[Writer] Stopped");
    }

    private void printReport() {
        System.out.println("\n==========================================");
        System.out.println("     DPI ENGINE - Multi-threaded Java     ");
        System.out.println("==========================================");
        System.out.println("\n==========================================");
        System.out.println("            PROCESSING REPORT             ");
        System.out.println("==========================================");
        System.out.printf ("  Total Packets : %d%n", totalPackets.get());
        System.out.println("------------------------------------------");
        System.out.printf ("  Forwarded     : %d%n", forwarded.get());
        System.out.printf ("  Dropped       : %d%n", dropped.get());
        System.out.println("------------------------------------------");
        System.out.println("  APPLICATION BREAKDOWN");
        System.out.println("------------------------------------------");

        appCounts.entrySet().stream()
            .filter(e -> e.getValue() > 0)
            .sorted((a, b) -> b.getValue() - a.getValue())
            .forEach(e -> {
                String tag = rules.getBlockedApps().contains(e.getKey())
                             ? " (BLOCKED)" : "";
                System.out.printf("  %-20s : %d%n", e.getKey() + tag, e.getValue());
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
        System.out.println("[Done] Output written to: " + outputFile);
    }
}