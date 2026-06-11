import java.io.*;

public class PcapReader {

    private FileInputStream fis;
    private boolean littleEndian;
    private boolean opened = false;

    // Opens the PCAP file and reads+validates the global header
    public void open(String filename) throws IOException {
        fis = new FileInputStream(filename);

        byte[] globalHeader = new byte[24];
        if (fis.read(globalHeader) != 24)
            throw new IOException("File too small to be a valid PCAP");

        // Magic number tells us byte order
        // Little-endian magic: D4 C3 B2 A1
        // Big-endian magic:    A1 B2 C3 D4
        int magic = readInt(globalHeader, 0, true); // try little-endian first
        if (magic == 0xA1B2C3D4) {
            littleEndian = true;
        } else if (magic == 0xD4C3B2A1) {
            littleEndian = false;
        } else {
            throw new IOException("Not a valid PCAP file (bad magic number)");
        }

        // We could read version, link type etc. from remaining
        // 20 bytes but for now we just skip them
        opened = true;
    }

    // Reads the next packet into the given ParsedPacket object
    // Returns true if a packet was read, false if EOF
    public boolean readNextPacket(ParsedPacket pkt) throws IOException {
        if (!opened) throw new IllegalStateException("Call open() first");

        // Read 16-byte packet header
        byte[] pktHeader = new byte[16];
        int bytesRead = fis.read(pktHeader);
        if (bytesRead == -1) return false; // EOF
        if (bytesRead != 16) throw new IOException("Truncated packet header");

        // Parse timestamp
        pkt.timestampSec  = readUInt(pktHeader, 0);
        pkt.timestampUsec = readUInt(pktHeader, 4);

        // Captured length = how many bytes of data follow
        long capturedLen  = readUInt(pktHeader, 8);
        // originalLen    = readUInt(pktHeader, 12); // not needed for simple version

        if (capturedLen > 65535)
            throw new IOException("Suspicious packet length: " + capturedLen);

        // Read packet data
        pkt.rawData = new byte[(int) capturedLen];
        int dataRead = fis.read(pkt.rawData);
        if (dataRead != (int) capturedLen)
            throw new IOException("Truncated packet data");

        return true;
    }

    public void close() throws IOException {
        if (fis != null) fis.close();
    }

    // ── Helper: read 4-byte signed int ──────────────────────────
    private int readInt(byte[] buf, int offset, boolean le) {
        if (le) {
            return (buf[offset]     & 0xFF)        |
                   ((buf[offset+1] & 0xFF) << 8)   |
                   ((buf[offset+2] & 0xFF) << 16)  |
                   ((buf[offset+3] & 0xFF) << 24);
        } else {
            return ((buf[offset]   & 0xFF) << 24)  |
                   ((buf[offset+1] & 0xFF) << 16)  |
                   ((buf[offset+2] & 0xFF) << 8)   |
                   (buf[offset+3]  & 0xFF);
        }
    }

    // Helper: read 4-byte value as unsigned long (no sign extension)
    private long readUInt(byte[] buf, int offset) {
        return readInt(buf, offset, littleEndian) & 0xFFFFFFFFL;
    }
}