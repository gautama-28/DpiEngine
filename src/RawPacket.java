public class RawPacket {

    public byte[] data;
    public long   timestampSec;
    public long   timestampUsec;

    // Poison pill — special sentinel object to signal shutdown
    // When an LB or FP receives this, it stops processing
    public boolean isPoisonPill;

    public RawPacket(byte[] data, long tsSec, long tsUsec) {
        this.data          = data;
        this.timestampSec  = tsSec;
        this.timestampUsec = tsUsec;
        this.isPoisonPill  = false;
    }

    // Private constructor for poison pill only
    private RawPacket() {
        this.isPoisonPill = true;
    }

    // Factory method — creates a poison pill sentinel
    public static RawPacket poisonPill() {
        return new RawPacket();
    }
}