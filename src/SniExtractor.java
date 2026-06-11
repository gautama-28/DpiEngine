public class SniExtractor {

    // Entry point — call this with the TCP payload bytes
    // Returns the domain name (e.g. "www.youtube.com") or null
    public static String extractSni(byte[] payload) {
        if (payload == null || payload.length < 5) return null;

        // ── Check: is this a TLS Handshake record? ────────────────
        // Byte 0: Content Type must be 0x16 (handshake)
        if ((payload[0] & 0xFF) != 0x16) return null;

        // Bytes 1-2: TLS version (0x0300, 0x0301, 0x0302, 0x0303)
        int tlsMajor = payload[1] & 0xFF;
        if (tlsMajor != 0x03) return null;

        // Bytes 3-4: record length
        int recordLen = readShort(payload, 3);
        if (payload.length < 5 + recordLen) return null;

        // ── Check: is this a Client Hello? ────────────────────────
        // Byte 5: Handshake type must be 0x01 (client_hello)
        if ((payload[5] & 0xFF) != 0x01) return null;

        // Bytes 6-8: handshake length (3 bytes, big-endian)
        // We don't strictly need this but good to validate
        // int hsLen = readInt24(payload, 6);

        // Byte 9-10: client version (skip, already checked TLS above)

        // ── Navigate past fixed fields ─────────────────────────────
        // Start reading from byte 11 (after content type, record len,
        // handshake type, handshake len, client version)

        int pos = 11; // start of Random field

        // Random: always exactly 32 bytes — skip it
        pos += 32;

        // ── Session ID (variable length) ───────────────────────────
        // 1 byte: session ID length
        if (pos >= payload.length) return null;
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen; // skip length byte + session ID bytes

        // ── Cipher Suites (variable length) ───────────────────────
        // 2 bytes: cipher suites length (in bytes, not count)
        if (pos + 2 > payload.length) return null;
        int cipherSuitesLen = readShort(payload, pos);
        pos += 2 + cipherSuitesLen; // skip length field + suite bytes

        // ── Compression Methods (variable length) ──────────────────
        // 1 byte: compression methods length
        if (pos >= payload.length) return null;
        int compressionLen = payload[pos] & 0xFF;
        pos += 1 + compressionLen; // skip length byte + method bytes

        // ── Extensions ─────────────────────────────────────────────
        // 2 bytes: total extensions length
        if (pos + 2 > payload.length) return null;
        int extensionsLen = readShort(payload, pos);
        pos += 2;

        int extensionsEnd = pos + extensionsLen;

        // ── Loop through each extension ────────────────────────────
        while (pos + 4 <= extensionsEnd && pos + 4 <= payload.length) {

            // 2 bytes: extension type
            int extType = readShort(payload, pos);
            pos += 2;

            // 2 bytes: extension data length
            int extLen = readShort(payload, pos);
            pos += 2;

            // Extension type 0x0000 = SNI
            if (extType == 0x0000) {
                return parseSniExtension(payload, pos, extLen);
            }

            // Not SNI — skip this extension's data
            pos += extLen;
        }

        return null; // no SNI extension found
    }

    // ── Parse the SNI extension data ──────────────────────────────
    //
    // Layout inside SNI extension:
    // [0-1]  SNI list length
    // [2]    Name type (0x00 = host_name)
    // [3-4]  Name length
    // [5+]   Name bytes (ASCII)

    private static String parseSniExtension(byte[] payload, int pos, int extLen) {
        if (pos + 2 > payload.length) return null;

        // SNI list length (usually same as extLen - 2, just skip it)
        // int sniListLen = readShort(payload, pos);
        pos += 2;

        // Name type: 0x00 = host_name (only defined type)
        if (pos >= payload.length) return null;
        int nameType = payload[pos] & 0xFF;
        pos += 1;

        if (nameType != 0x00) return null; // unknown type, skip

        // Name length
        if (pos + 2 > payload.length) return null;
        int nameLen = readShort(payload, pos);
        pos += 2;

        // Name bytes — plain ASCII domain name
        if (pos + nameLen > payload.length) return null;
        return new String(payload, pos, nameLen); // e.g. "www.youtube.com"
    }

    // ── Also handle plain HTTP (unencrypted) ──────────────────────
    // For HTTP, the Host header is plaintext in the payload
    // e.g. "GET / HTTP/1.1\r\nHost: www.example.com\r\n..."

    public static String extractHttpHost(byte[] payload) {
        if (payload == null || payload.length == 0) return null;

        String text = new String(payload);

        // Quick check: does it look like HTTP?
        if (!text.startsWith("GET ")  && !text.startsWith("POST ") &&
            !text.startsWith("HEAD ") && !text.startsWith("PUT ")  &&
            !text.startsWith("CONNECT ")) return null;

        // Find "Host:" header (case-insensitive)
        String lower = text.toLowerCase();
        int hostIdx = lower.indexOf("\nhost:");
        if (hostIdx == -1) return null;

        int valueStart = hostIdx + 6; // skip "\nhost:"
        // skip any spaces
        while (valueStart < text.length() && text.charAt(valueStart) == ' ')
            valueStart++;

        int valueEnd = text.indexOf("\r", valueStart);
        if (valueEnd == -1) valueEnd = text.indexOf("\n", valueStart);
        if (valueEnd == -1) valueEnd = text.length();

        String host = text.substring(valueStart, valueEnd).trim();
        return host.isEmpty() ? null : host;
    }

    // ── Helpers ───────────────────────────────────────────────────

    // Read 2 bytes big-endian as unsigned int
    private static int readShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    // Read 3 bytes big-endian as int (used in handshake length)
    private static int readInt24(byte[] data, int offset) {
        return ((data[offset]   & 0xFF) << 16) |
               ((data[offset+1] & 0xFF) << 8)  |
                (data[offset+2] & 0xFF);
    }
}