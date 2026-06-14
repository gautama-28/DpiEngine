import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class FastPath implements Runnable {

    private final int id;
    private final BlockingQueue<RawPacket>    inputQueue;
    private final BlockingQueue<ParsedPacket> outputQueue;
    private final RuleManager                 rules;

    // Private flow table — no locking needed, only this thread accesses it
    private final Map<FiveTuple, FlowState> flowTable = new HashMap<>();

    // Shared atomic counters (safe to increment from multiple FP threads)
    private final AtomicInteger totalPackets;
    private final AtomicInteger droppedPackets;
    private final AtomicInteger forwardedPackets;

    public FastPath(int id,
                    BlockingQueue<RawPacket>    inputQueue,
                    BlockingQueue<ParsedPacket> outputQueue,
                    RuleManager                 rules,
                    AtomicInteger               totalPackets,
                    AtomicInteger               droppedPackets,
                    AtomicInteger               forwardedPackets) {
        this.id               = id;
        this.inputQueue       = inputQueue;
        this.outputQueue      = outputQueue;
        this.rules            = rules;
        this.totalPackets     = totalPackets;
        this.droppedPackets   = droppedPackets;
        this.forwardedPackets = forwardedPackets;
    }

    public BlockingQueue<RawPacket> getInputQueue() {
        return inputQueue;
    }

    @Override
    public void run() {
        System.out.println("[FP" + id + "] Started");

        while (true) {
            try {
                RawPacket raw = inputQueue.take();

                if (raw.isPoisonPill) {
                    System.out.println("[FP" + id + "] Received poison pill, shutting down");
                    // Signal writer that one FP is done
                    // (writer waits for all FPs to finish)
                    outputQueue.put(createPoisonParsedPacket());
                    break;
                }

                totalPackets.incrementAndGet();
                processPacket(raw);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        System.out.println("[FP" + id + "] Stopped. Flows tracked: " + flowTable.size());
    }

    private void processPacket(RawPacket raw) throws InterruptedException {

        // Step 1: Parse headers
        ParsedPacket pkt = new ParsedPacket();
        pkt.rawData       = raw.data;
        pkt.timestampSec  = raw.timestampSec;
        pkt.timestampUsec = raw.timestampUsec;

        PacketParser.parse(pkt);

        // Step 2: Build five-tuple and look up flow
        FiveTuple  tuple = pkt.toFiveTuple();
        FlowState  flow  = flowTable.computeIfAbsent(tuple, k -> new FlowState());

        // Step 3: Already blocked flow — drop immediately
        if (flow.blocked) {
            droppedPackets.incrementAndGet();
            return;
        }

        // Step 4: Try SNI extraction if not yet seen
        if (!flow.sniSeen && pkt.isTcp
                          && pkt.payload != null
                          && pkt.payload.length > 0) {

            String sni = SniExtractor.extractSni(pkt.payload);
            if (sni == null) sni = SniExtractor.extractHttpHost(pkt.payload);

            if (sni != null) {
                AppType app  = DpiEngine.classifyFromSni(sni);
                pkt.sni      = sni;
                pkt.appType  = app;
                flow.sni     = sni;
                flow.appType = app;
                flow.sniSeen = true;
            } else {
                pkt.appType  = DpiEngine.classifyFromPort(pkt);
                flow.appType = pkt.appType;
            }

        } else if (flow.sniSeen) {
            pkt.sni     = flow.sni;
            pkt.appType = flow.appType;
        } else {
            pkt.appType = DpiEngine.classifyFromPort(pkt);
        }

        // Step 5: Check rules
        boolean block = rules.shouldBlock(pkt);
        if (!block && flow.sniSeen) block = rules.shouldBlockFlow(flow);

        if (block) {
            flow.blocked = true;
            pkt.blocked  = true;
            droppedPackets.incrementAndGet();
            return; // don't forward
        }

        // Step 6: Forward to output queue
        forwardedPackets.incrementAndGet();
        outputQueue.put(pkt);
    }

    // Sentinel ParsedPacket to signal writer that this FP is done
    private ParsedPacket createPoisonParsedPacket() {
        ParsedPacket poison = new ParsedPacket();
        poison.blocked = true;   // reuse blocked flag as poison marker
        poison.rawData = null;   // null rawData = poison pill
        return poison;
    }
}