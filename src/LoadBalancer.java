import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class LoadBalancer implements Runnable {

    private final int id;
    private final BlockingQueue<RawPacket> inputQueue;
    private final BlockingQueue<RawPacket>[] fpQueues; // one queue per FP
    private final int numFPs;

    public LoadBalancer(int id, BlockingQueue<RawPacket>[] fpQueues) {
        this.id         = id;
        this.fpQueues   = fpQueues;
        this.numFPs     = fpQueues.length;
        this.inputQueue = new LinkedBlockingQueue<>(1000); // bounded: backpressure
    }

    // Reader pushes packets here
    public BlockingQueue<RawPacket> getInputQueue() {
        return inputQueue;
    }

    @Override
    public void run() {
        System.out.println("[LB" + id + "] Started");

        while (true) {
            try {
                RawPacket pkt = inputQueue.take(); // blocks until item available

                if (pkt.isPoisonPill) {
                    // Forward one poison pill to EACH FP so they all shut down
                    System.out.println("[LB" + id + "] Received poison pill, shutting down");
                    for (BlockingQueue<RawPacket> fpQueue : fpQueues) {
                        fpQueue.put(RawPacket.poisonPill());
                    }
                    break; // exit loop, thread ends
                }

                // Route packet to FP based on five-tuple hash
                // We do a quick hash here without full parsing:
                // use first bytes of data as a fast approximation
                int fpIdx = selectFastPath(pkt.data);
                fpQueues[fpIdx].put(pkt);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        System.out.println("[LB" + id + "] Stopped");
    }

    // Hash raw packet bytes to select a Fast Path
    // We use IP src+dst bytes (bytes 26-33) for consistent routing
    // Same five-tuple always hashes to same FP
    private int selectFastPath(byte[] data) {
        // Ethernet = 14 bytes, IP src starts at byte 26, dst at 30
        // TCP src port at 34, dst port at 36
        if (data.length < 38) return 0; // too small, send to FP0

        int hash = 0;
        // src IP (4 bytes at offset 26)
        hash ^= (data[26] & 0xFF) << 24;
        hash ^= (data[27] & 0xFF) << 16;
        hash ^= (data[28] & 0xFF) << 8;
        hash ^= (data[29] & 0xFF);
        // dst IP (4 bytes at offset 30)
        hash ^= (data[30] & 0xFF) << 24;
        hash ^= (data[31] & 0xFF) << 16;
        hash ^= (data[32] & 0xFF) << 8;
        hash ^= (data[33] & 0xFF);
        // src port (2 bytes at offset 34)
        hash ^= (data[34] & 0xFF) << 8;
        hash ^= (data[35] & 0xFF);
        // dst port (2 bytes at offset 36)
        hash ^= (data[36] & 0xFF) << 8;
        hash ^= (data[37] & 0xFF);

        // Make positive before modulo
        return Math.abs(hash) % numFPs;
    }
}