# DPI Engine - Deep Packet Inspection System

Ever tried opening a website only to find that it was blocked by your ISP, company network, college Wi-Fi, or even a government firewall?

How does a network know you're visiting YouTube, Facebook, Netflix, or Discord when the traffic is protected by HTTPS encryption?

The answer lies in **Deep Packet Inspection (DPI)**.

To understand how modern network filtering works, I built a complete DPI Engine from scratch in Java. The system reads raw packet captures, parses Ethernet/IP/TCP layers, extracts TLS SNI information from HTTPS handshakes, classifies applications, tracks flows, and applies real-world blocking rules exactly like a simplified network firewall.

**Not interested in the contents and want to test it yourself directly?**
[Click Here](#9-building-and-running) to navigate to building and running commands.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [Deep Dive: Each Component](#6-deep-dive-each-component)
7. [How SNI Extraction Works](#7-how-sni-extraction-works)
8. [How Blocking Works](#8-how-blocking-works)
9. [Building and Running](#9-building-and-running)
10. [Rules Configuration](#10-rules-configuration)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses

- **ISPs**: Throttle or block certain applications (e.g., BitTorrent, YouTube)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites for children
- **Security**: Detect malware signatures or intrusion attempts
- **Network Analytics**: Understand what applications are consuming bandwidth

### What Our DPI Engine Does

```
Input PCAP File        DPI Engine (Java)         Output PCAP File
+---------------+      +------------------+      +---------------+
| Raw network   |      | 1. Parse headers |      | Filtered      |
| traffic       | ---> | 2. Extract SNI   | ---> | traffic       |
| (captured by  |      | 3. Classify app  |      | (blocked pkts |
|  Wireshark)   |      | 4. Apply rules   |      |  removed)     |
+---------------+      | 5. Write report  |      +---------------+
                        +------------------+
                                |
                                v
                        +------------------+
                        | Console Report:  |
                        | - App breakdown  |
                        | - Domains found  |
                        | - Drop stats     |
                        +------------------+
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, your data travels through multiple protocol layers. Each layer adds its own header:

```
+----------------------------------------------------------+
| Layer 7: Application   |  HTTP, TLS, DNS                 |
+----------------------------------------------------------+
| Layer 4: Transport     |  TCP (reliable), UDP (fast)     |
+----------------------------------------------------------+
| Layer 3: Network       |  IP addresses (routing)         |
+----------------------------------------------------------+
| Layer 2: Data Link     |  MAC addresses (local network)  |
+----------------------------------------------------------+
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** — headers wrapped inside headers:

```
+--------------------------------------------------------------------+
| Ethernet Header (14 bytes)                                         |
|  +----------------------------------------------------------------+|
|  | IP Header (20+ bytes)                                          ||
|  |  +------------------------------------------------------------+||
|  |  | TCP Header (20+ bytes)                                     |||
|  |  |  +--------------------------------------------------------+|||
|  |  |  | Payload (Application Data)                             ||||
|  |  |  | e.g., TLS Client Hello containing SNI field            ||||
|  |  |  +--------------------------------------------------------+|||
|  |  +------------------------------------------------------------+||
|  +----------------------------------------------------------------+|
+--------------------------------------------------------------------+
```

Our `PacketParser.java` peels off each layer one by one, reading the exact byte offsets defined by each protocol standard.

### The Five-Tuple

A **connection** (also called a "flow") is uniquely identified by exactly 5 values:

| Field | Example | Purpose |
|---|---|---|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 142.250.185.110 | Where it's going |
| Source Port | 54321 | Sender's application port |
| Destination Port | 443 | Service (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why this matters:**
- All packets with the same five-tuple belong to the same connection
- Once we identify a connection as YouTube traffic, all its future packets are also YouTube
- If we block a connection, we block it at the flow level — not just one packet
- `FiveTuple.java` implements `hashCode()` and `equals()` so it works as a `HashMap` key

### What is SNI?

**Server Name Indication (SNI)** is a field inside the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a **Client Hello** message to start the TLS handshake
2. This message includes the destination domain name in **plaintext** (not yet encrypted!)
3. The server reads the SNI to decide which SSL certificate to present

```
TLS Client Hello (plaintext, visible to DPI):
+-- Content Type: Handshake (0x16)
+-- TLS Version: 0x0303
+-- Handshake Type: Client Hello (0x01)
+-- Random: [32 bytes]
+-- Session ID: [variable]
+-- Cipher Suites: [list of supported ciphers]
+-- Extensions:
    +-- SNI Extension (type 0x0000):
        +-- Server Name: "www.youtube.com"  <-- WE EXTRACT THIS
```

**This is the key insight of DPI**: Even though HTTPS traffic is encrypted, the destination domain name leaks out in the very first packet of every connection.

---

## 3. Project Overview

### What This Project Does

```
generate_test_pcap.py        DPI Engine (Java)           output_java.pcap
+---------------------+      +----------------------+     +---------------+
| Creates test PCAP   |      | PcapReader.java      |     | Allowed       |
| with:               | ---> | PacketParser.java    | --> | packets only  |
| - TLS connections   |      | SniExtractor.java    |     | (blocked ones |
| - HTTP traffic      |      | FlowTracker.java     |     |  dropped)     |
| - DNS queries       |      | RuleManager.java     |     +---------------+
| - Blocked IPs       |      | Main.java            |
+---------------------+      +----------------------+
                                       |
                              rules.txt (config)
                              block-app YOUTUBE
                              block-domain facebook
                              block-ip 192.168.1.50
```

### Design Philosophy

This is a **single-threaded, file-based** DPI engine. It reads an existing `.pcap` capture file, processes every packet sequentially, and writes a filtered `.pcap` file. This design is:

- Easy to understand and debug
- Perfect for learning how DPI works
- Sufficient for moderate-sized capture files
- Zero external dependencies — pure Java SE

---

## 4. File Structure

```
DpiEngine/
|
+-- src/                          <- All Java source files
|   +-- AppType.java              <- Enum: YOUTUBE, FACEBOOK, DNS, etc.
|   +-- FiveTuple.java            <- Connection key (5-tuple with hashCode/equals)
|   +-- ParsedPacket.java         <- Data holder for one parsed packet
|   +-- FlowState.java            <- Per-connection state (SNI seen? blocked?)
|   +-- PcapReader.java           <- Reads binary .pcap file format
|   +-- PacketParser.java         <- Ethernet / IP / TCP / UDP header parsing
|   +-- SniExtractor.java         <- TLS Client Hello -> domain name
|   +-- RuleManager.java          <- Blocking rules: IP / app / domain
|   +-- FlowTracker.java          <- HashMap-based flow table
|   +-- Main.java                 <- Orchestrator + report printer
|
+-- generate_test_pcap.py         <- Python script to generate test traffic
+-- test_dpi.pcap                 <- Sample capture (77 packets, 18 domains)
+-- rules.txt                     <- Blocking rules config file
+-- output_java.pcap              <- Generated after running the engine
+-- README.md                     <- This file
```

### Dependency Graph

```
Main.java
  |-- PcapReader.java       (reads raw bytes from file)
  |-- PacketParser.java     (fills ParsedPacket fields)
  |     |-- ParsedPacket.java
  |-- SniExtractor.java     (extracts domain from payload)
  |-- FlowTracker.java      (manages flow table)
  |     |-- FiveTuple.java  (HashMap key)
  |     |-- FlowState.java  (per-flow data)
  |-- RuleManager.java      (decides block/forward)
        |-- AppType.java    (enum used in rules)
```

---

## 5. The Journey of a Packet

Let's trace a single HTTPS packet (TLS Client Hello to YouTube) through every stage of the engine.

### Step 1: Read from PCAP File (`PcapReader.java`)

```java
PcapReader reader = new PcapReader();
reader.open("test_dpi.pcap");

ParsedPacket pkt = new ParsedPacket();
while (reader.readNextPacket(pkt)) {
    // pkt.rawData contains the full packet bytes
    // pkt.timestampSec, pkt.timestampUsec are set
}
```

**What happens inside `open()`:**

1. Opens the file with `FileInputStream`
2. Reads the 24-byte PCAP global header
3. Checks the magic number to determine byte order:

```
PCAP Global Header (24 bytes):
Bytes  0- 3: Magic = 0xA1B2C3D4 (little-endian) or 0xD4C3B2A1 (big-endian)
Bytes  4- 5: Major version (always 2)
Bytes  6- 7: Minor version (always 4)
Bytes  8-11: GMT offset (usually 0)
Bytes 12-15: Timestamp accuracy (usually 0)
Bytes 16-19: Snapshot length (max packet size, usually 65535)
Bytes 20-23: Link type (1 = Ethernet)
```

**What happens inside `readNextPacket()`:**

```
PCAP Packet Record:
+------------------------+   <- 16-byte packet header
| ts_sec    (4 bytes)    |   Timestamp: seconds
| ts_usec   (4 bytes)    |   Timestamp: microseconds
| incl_len  (4 bytes)    |   How many bytes follow (N)
| orig_len  (4 bytes)    |   Original size on wire
+------------------------+
| Packet Data (N bytes)  |   <- Raw Ethernet frame
+------------------------+
```

**The byte order problem (why we use `& 0xFF`):**

Java's `byte` is signed (-128 to 127). When reading binary data:
```java
byte b = (byte) 0xFF;   // This is -1 in Java!
int wrong = b;          // -1 (sign-extended, wrong!)
int right = b & 0xFF;   // 255 (masked to 8 bits, correct!)
```

Every byte read from the PCAP file is masked with `& 0xFF` or `& 0xFFFFFFFFL` to prevent sign extension.

---

### Step 2: Parse Protocol Headers (`PacketParser.java`)

```java
PacketParser.parse(pkt);
// After this call, pkt fields are filled:
// pkt.srcIp, pkt.dstIp, pkt.srcPort, pkt.dstPort
// pkt.protocol, pkt.isTcp, pkt.isUdp, pkt.payload
```

**Ethernet Header parsing (bytes 0-13):**

```
rawData[]:
Offset  0: Destination MAC (6 bytes) -> pkt.dstMac = "AA:BB:CC:DD:EE:FF"
Offset  6: Source MAC      (6 bytes) -> pkt.srcMac = "00:11:22:33:44:55"
Offset 12: EtherType       (2 bytes) -> 0x0800 = IPv4 (we only handle IPv4)
```

**IP Header parsing (starts at offset 14):**

```
rawData[14]:
Offset  0: Version(4 bits) + IHL(4 bits)
           IHL = header length in 4-byte units
           IHL=5 means 20 bytes (standard, no options)
           IHL=6 means 24 bytes (with IP options)
Offset  9: Protocol -> 6=TCP, 17=UDP
Offset 12: Source IP      (4 bytes) -> pkt.srcIp = "192.168.1.100"
Offset 16: Destination IP (4 bytes) -> pkt.dstIp = "142.250.185.110"
```

**TCP Header parsing (starts at offset 14 + ipHeaderLen):**

```
Offset  0: Source Port      (2 bytes) -> pkt.srcPort = 54321
Offset  2: Destination Port (2 bytes) -> pkt.dstPort = 443
Offset  4: Sequence Number  (4 bytes) [not used]
Offset  8: Ack Number       (4 bytes) [not used]
Offset 12: Data Offset      (upper 4 bits) = TCP header length in 4-byte units
           DataOffset=5 means 20 bytes (standard TCP, no options)
Offset 13: Flags            (SYN=0x02, ACK=0x10, PSH=0x08, etc.)
```

**How offsets stack for a standard packet:**

```
rawData[]:
| 0      | 14     | 34     | 54      |
| Eth    | IP Hdr | TCP    | Payload |
| 14 B   | 20 B   | 20 B   | ...     |

pkt.payloadOffset = 14 + 20 + 20 = 54
pkt.payload = rawData[54 .. end]
```

**UDP Header parsing (starts at offset 14 + ipHeaderLen):**

```
Offset 0: Source Port      (2 bytes)
Offset 2: Destination Port (2 bytes)
Offset 4: Length           (2 bytes) = 8 + payload length
Offset 6: Checksum         (2 bytes) [not used]
Payload starts at offset 8 (UDP header is always fixed 8 bytes)
```

---

### Step 3: Build Five-Tuple and Look Up Flow

```java
FiveTuple tuple = pkt.toFiveTuple();
FlowState  flow  = tracker.getOrCreate(tuple);
```

**How `FiveTuple` normalization works:**

A TCP connection has two directions: client→server and server→client. Without normalization, the SYN-ACK reply from the server would create a *separate* flow entry because src/dst are swapped.

`FiveTuple.java` normalizes this by always putting the lexicographically smaller IP first:

```java
boolean flip = srcIp.compareTo(dstIp) > 0 ||
               (srcIp.equals(dstIp) && srcPort > dstPort);

if (flip) {
    // swap src <-> dst so both directions map to same key
}
```

**Result:**
```
Client Hello (192.168.1.100:54321 -> 142.250.185.110:443)
SYN-ACK     (142.250.185.110:443  -> 192.168.1.100:54321)

Both normalize to the same FiveTuple key in the HashMap.
```

---

### Step 4: Check if Flow is Already Blocked

```java
if (flow.blocked) {
    dropped++;
    continue; // skip all further processing
}
```

This is the **fast path** — once a flow is identified and blocked, all subsequent packets of that flow are dropped immediately without any further parsing. This mirrors how real DPI engines work.

---

### Step 5: Extract SNI (`SniExtractor.java`)

```java
String sni = SniExtractor.extractSni(pkt.payload);

// Fallback for unencrypted HTTP:
if (sni == null) sni = SniExtractor.extractHttpHost(pkt.payload);
```

This is the core DPI step — detailed in [Section 7](#7-how-sni-extraction-works).

---

### Step 6: Classify the Application

```java
AppType app = classifyFromSni(sni);
// "www.youtube.com" -> AppType.YOUTUBE
// "www.facebook.com" -> AppType.FACEBOOK
// "discord.com" -> AppType.DISCORD
```

Classification uses simple substring matching:

```java
if (s.contains("youtube") || s.contains("googlevideo")) return AppType.YOUTUBE;
if (s.contains("facebook") || s.contains("fbcdn"))      return AppType.FACEBOOK;
if (s.contains("netflix"))                               return AppType.NETFLIX;
// ... 20 more patterns
```

If no SNI is found, we fall back to **port-based classification**:

```java
if (dstPort == 53)  return AppType.DNS;
if (dstPort == 80)  return AppType.HTTP;
if (dstPort == 443) return AppType.HTTPS;
```

---

### Step 7: Check Blocking Rules (`RuleManager.java`)

```java
boolean block = rules.shouldBlock(pkt);
```

Three checks happen in order:

```
Is pkt.srcIp in blockedIps?          -> DROP
Is pkt.appType in blockedApps?       -> DROP
Does pkt.sni contain blockedDomain?  -> DROP
Otherwise                            -> FORWARD
```

---

### Step 8: Forward or Drop

```java
if (block) {
    flow.blocked = true;  // mark entire flow as blocked
    dropped++;
} else {
    writePacket(out, pkt);  // write to output PCAP
    forwarded++;
}
```

When a flow is marked blocked, **all future packets** of that connection are dropped in Step 4 without re-checking rules. This is correct behavior — once we know a connection goes to YouTube and YouTube is blocked, every packet of that connection must be dropped.

---

### Step 9: Print Report

After processing all packets, `Main.java` prints a full summary:

```
==========================================
            PROCESSING REPORT
==========================================
  Total Packets : 77
  TCP Packets   : 73
  UDP Packets   : 4
------------------------------------------
  Forwarded     : 69
  Dropped       : 8
------------------------------------------
  APPLICATION BREAKDOWN
------------------------------------------
  HTTPS          : 37
  UNKNOWN        : 18
  DNS            : 4
  YOUTUBE(BLOCKED: 1
  FACEBOOK(BLOCKED: 1
  ...
------------------------------------------
  DETECTED DOMAINS / SNIs
------------------------------------------
  www.youtube.com                -> YOUTUBE
  www.facebook.com               -> FACEBOOK
  github.com                     -> GITHUB
  ...
==========================================
```

---

## 6. Deep Dive: Each Component

### `AppType.java`

A simple Java `enum` listing every application the engine can recognize:

```java
public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS,
    YOUTUBE, FACEBOOK, GOOGLE, NETFLIX,
    TWITTER, INSTAGRAM, TIKTOK, GITHUB,
    WHATSAPP, DISCORD, ZOOM, TELEGRAM,
    SPOTIFY, AMAZON, MICROSOFT, APPLE, CLOUDFLARE
}
```

**Why an enum?** Enums can be used in `HashSet<AppType>` for O(1) blocking lookups, in `switch` statements, and in the report printer. Adding a new app just means adding one enum value and one `contains()` check in `classifyFromSni()`.

---

### `FiveTuple.java`

The connection identifier. **Must** implement `hashCode()` and `equals()` correctly to be used as a `HashMap` key.

```java
@Override
public int hashCode() {
    return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
}

@Override
public boolean equals(Object o) {
    FiveTuple t = (FiveTuple) o;
    return srcPort == t.srcPort && dstPort == t.dstPort &&
           protocol == t.protocol &&
           srcIp.equals(t.srcIp) && dstIp.equals(t.dstIp);
}
```

If `hashCode()` or `equals()` were wrong, flows would never match and every packet would create a new entry — the flow table would never work.

---

### `ParsedPacket.java`

A data container (no logic) holding everything we extract from one packet:

| Field | Type | Set by | Contains |
|---|---|---|---|
| `rawData` | `byte[]` | PcapReader | Full Ethernet frame |
| `timestampSec` | `long` | PcapReader | Unix timestamp |
| `srcIp`, `dstIp` | `String` | PacketParser | "192.168.1.100" |
| `srcPort`, `dstPort` | `int` | PacketParser | 0-65535 |
| `protocol` | `int` | PacketParser | 6=TCP, 17=UDP |
| `isTcp`, `isUdp` | `boolean` | PacketParser | Layer 4 type |
| `payload` | `byte[]` | PacketParser | TCP/UDP payload |
| `sni` | `String` | Main.java | "www.youtube.com" |
| `appType` | `AppType` | Main.java | YOUTUBE, DNS, etc. |
| `blocked` | `boolean` | Main.java | Was this packet dropped? |

---

### `FlowState.java`

Tracks what we know about each connection:

```java
public class FlowState {
    public AppType appType = AppType.UNKNOWN;
    public String  sni     = null;
    public boolean blocked  = false;
    public boolean sniSeen  = false;
}
```

`sniSeen` is particularly important — without it, we would attempt SNI extraction on every single packet of a connection, wasting time. Once we've seen the Client Hello and extracted the SNI, `sniSeen` is set to `true` and subsequent packets skip directly to the blocking check.

---

### `PcapReader.java`

Reads the binary PCAP format using `FileInputStream`. Key design decisions:

**Little-endian vs big-endian:** PCAP files can be either, determined by the magic number. Our reader detects this at open time and applies the right byte order for all subsequent reads.

**Why not use `DataInputStream`?** `DataInputStream` always reads big-endian. Since PCAP files from most systems (Windows, Linux x86) are little-endian, we handle byte order manually for correctness.

```java
// Read 4 bytes in little-endian order:
private int readInt(byte[] buf, int offset, boolean le) {
    if (le) {
        return (buf[offset]     & 0xFF)       |
               ((buf[offset+1] & 0xFF) << 8)  |
               ((buf[offset+2] & 0xFF) << 16) |
               ((buf[offset+3] & 0xFF) << 24);
    }
    // big-endian: reverse the shift order
}
```

---

### `PacketParser.java`

Static utility class — all methods are `static`, no instance needed. Call `PacketParser.parse(pkt)` and all fields of `pkt` are filled.

**Why static?** The parser holds no state between packets. Making it static avoids unnecessary object creation and makes the intent clear — this is a pure function that transforms raw bytes into structured data.

**IHL (IP Header Length) calculation:**

```java
int ihl = (data[ipOffset] & 0x0F);  // lower 4 bits
pkt.ipHeaderLen = ihl * 4;          // value is in 4-byte units

// Standard IP header: IHL=5, headerLen=20 bytes
// IP with options:    IHL=6, headerLen=24 bytes
```

**TCP Data Offset calculation:**

```java
int dataOffset = (data[offset + 12] & 0xF0) >> 4;  // upper 4 bits
pkt.tcpHeaderLen = dataOffset * 4;

// Standard TCP: dataOffset=5, headerLen=20 bytes
// TCP with options: dataOffset=8, headerLen=32 bytes (e.g. timestamps)
```

---

### `SniExtractor.java`

The most important class — described in full detail in [Section 7](#7-how-sni-extraction-works).

Also handles plain HTTP via `extractHttpHost()`:

```java
// Looks for: "GET / HTTP/1.1\r\nHost: www.example.com\r\n"
String lower = text.toLowerCase();
int hostIdx = lower.indexOf("\nhost:");
// extract value between "Host: " and "\r\n"
```

---

### `RuleManager.java`

Three `HashSet` collections for O(1) blocking lookups:

```java
private final Set<String>   blockedIps     = new HashSet<>();
private final Set<AppType>  blockedApps    = new HashSet<>();
private final Set<String>   blockedDomains = new HashSet<>();
```

**Domain matching uses substring search**, not exact match:

```java
// blocking "facebook" will match:
// "www.facebook.com"     -> BLOCKED
// "static.facebook.net"  -> BLOCKED
// "fbcdn.net"            -> NOT BLOCKED (use "fbcdn" to catch this)
```

Two check methods:
- `shouldBlock(ParsedPacket pkt)` — for packets where we just extracted SNI
- `shouldBlockFlow(FlowState flow)` — for subsequent packets of an identified flow

---

### `FlowTracker.java`

Wraps a `HashMap<FiveTuple, FlowState>`:

```java
private final Map<FiveTuple, FlowState> table = new HashMap<>();

public FlowState getOrCreate(FiveTuple key) {
    return table.computeIfAbsent(key, k -> new FlowState());
}
```

`computeIfAbsent` is used instead of `get()` + `put()` — it atomically returns the existing value or creates and inserts a new one, in a single call.

Also provides `updateFlow()` to record SNI/app once identified, and `printSummary()` for the final report.

---

### `Main.java`

The orchestrator. Responsibilities:

1. Parse command-line arguments (`--block-app`, `--block-ip`, `--block-domain`)
2. Load `rules.txt` via `loadRulesFromFile()`
3. Open input PCAP and output PCAP
4. Run the main processing loop (Steps 1-8 above)
5. Collect stats (`appCounts`, `sniAppMap`)
6. Print the final report

**The processing loop in pseudocode:**

```
while (reader has packets):
    read raw packet bytes
    parse Ethernet/IP/TCP/UDP headers
    build FiveTuple, get/create FlowState

    if flow.blocked:
        dropped++; continue

    if tcp AND payload exists AND SNI not yet seen:
        try TLS SNI extraction
        if null: try HTTP Host extraction
        if found: classify app, update flow

    check blocking rules
    if blocked: mark flow blocked, dropped++
    else: write packet to output, forwarded++

    update app stats
```

---

## 7. How SNI Extraction Works

### The TLS Handshake Timeline

```
Browser                                    YouTube Server
  |                                              |
  |------- TCP SYN --------------------------->  |
  |<------ TCP SYN-ACK ------------------------  |
  |------- TCP ACK --------------------------->  |
  |                                              |
  |------- TLS Client Hello ------------------>  |  <- WE READ THIS
  |        [SNI: "www.youtube.com" IN PLAINTEXT] |
  |                                              |
  |<------ TLS Server Hello -------------------  |
  |        [certificate, cipher choice]          |
  |                                              |
  |<============ Encrypted from here on ======>  |
  |   (we can't read anything past this point)   |
```

### TLS Client Hello Byte Layout

```
TCP Payload bytes:

[0]      0x16          <- Content Type: Handshake
[1]      0x03          <- TLS Major Version
[2]      0x01/03       <- TLS Minor Version (01=TLS1.0, 03=TLS1.2)
[3-4]    record_len    <- Length of handshake data that follows
[5]      0x01          <- Handshake Type: Client Hello
[6-8]    hs_len        <- 3-byte handshake length
[9-10]   client_ver    <- Client's max supported TLS version
[11-42]  random        <- 32 random bytes (skip these)
[43]     sid_len       <- Session ID length (0 if no session)
[44+]    session_id    <- Session ID bytes (variable, skip)
[?]      cs_len(2)     <- Cipher Suites length in bytes
[?]      cipher_suites <- List of cipher suite codes (skip)
[?]      comp_len(1)   <- Compression methods length
[?]      comp_methods  <- Compression methods (skip)
[?]      ext_len(2)    <- Total extensions length

Extensions loop:
[?]      ext_type(2)   <- Extension type (0x0000 = SNI!)
[?]      ext_len(2)    <- This extension's data length
[?]      ext_data      <- Extension payload

SNI Extension data (when ext_type == 0x0000):
[0-1]    list_len      <- SNI list length
[2]      0x00          <- Name type: host_name
[3-4]    name_len      <- Domain name length
[5+]     name_bytes    <- "www.youtube.com" in ASCII  <-- GOAL
```

### Navigation Strategy

The challenge is that Session ID, Cipher Suites, and Compression are **variable length** — we cannot use fixed offsets past byte 42. We must read each length field and skip forward:

```java
int pos = 11;                         // start of Random

pos += 32;                            // skip Random (always 32 bytes)

int sidLen = payload[pos] & 0xFF;
pos += 1 + sidLen;                    // skip Session ID

int csLen = readShort(payload, pos);
pos += 2 + csLen;                     // skip Cipher Suites

int compLen = payload[pos] & 0xFF;
pos += 1 + compLen;                   // skip Compression

int extLen = readShort(payload, pos);
pos += 2;                             // enter Extensions region

// Loop through extensions until we find type 0x0000
while (pos + 4 <= pos + extLen) {
    int type = readShort(payload, pos); pos += 2;
    int len  = readShort(payload, pos); pos += 2;

    if (type == 0x0000) {
        return parseSniExtension(payload, pos);
    }
    pos += len;  // skip this extension
}
```

### HTTP Host Extraction

For unencrypted HTTP traffic (port 80), the domain is in the `Host:` header:

```
GET /index.html HTTP/1.1
Host: www.example.com         <- we extract this
User-Agent: Mozilla/5.0
Accept: */*
```

```java
int hostIdx = lower.indexOf("\nhost:");
// find end of value at \r or \n
// return trimmed substring
```

---

## 8. How Blocking Works

### Rule Types

| Rule Type | Example in rules.txt | What Gets Blocked |
|---|---|---|
| IP | `block-ip 192.168.1.50` | All packets from this source IP |
| App | `block-app YOUTUBE` | All flows classified as YouTube |
| Domain | `block-domain facebook` | Any SNI containing "facebook" |

### The Blocking Decision Flow

```
Packet arrives
      |
      v
+---------------------+
| Is flow.blocked?    |--YES--> DROP (fast path, no further checks)
+---------------------+
      | NO
      v
+---------------------+
| Extract SNI         |
| Classify app        |
+---------------------+
      |
      v
+---------------------+
| src IP blocked?     |--YES--> mark flow blocked -> DROP
+---------------------+
      | NO
      v
+---------------------+
| app type blocked?   |--YES--> mark flow blocked -> DROP
+---------------------+
      | NO
      v
+---------------------+
| domain substring    |--YES--> mark flow blocked -> DROP
| matches blocked     |
| domain?             |
+---------------------+
      | NO
      v
   FORWARD -> write to output.pcap
```

### Flow-Level Blocking Example

```
Connection to YouTube (5-tuple: 192.168.1.100:54321 -> 142.250.185.110:443):

Packet 1: TCP SYN        -> no payload, no SNI -> FORWARD
Packet 2: TCP SYN-ACK    -> no payload, no SNI -> FORWARD
Packet 3: TCP ACK        -> no payload, no SNI -> FORWARD
Packet 4: TLS ClientHello -> SNI: www.youtube.com -> AppType: YOUTUBE
                          -> YOUTUBE is in blockedApps
                          -> flow.blocked = true -> DROP
Packet 5: TLS data       -> flow.blocked == true -> DROP (fast path)
Packet 6: TLS data       -> flow.blocked == true -> DROP (fast path)
...all remaining packets -> DROP (fast path)
```

**Why do packets 1-3 get forwarded?** We have no information yet about what application this connection belongs to. The Client Hello (packet 4) is the first packet that contains the SNI. In a real inline DPI system, those early packets could also be buffered and dropped retroactively, but for this file-based implementation, they are forwarded.

---

## 9. Building and Running

### Prerequisites

- **Java SE 8 or higher** (uses `java.util`, `java.io` only — no external dependencies)
- **Python 3** (only needed to regenerate test data)
- **Windows / Linux / macOS** (platform independent)

### Compile

```bash
cd DpiEngine/src
javac -encoding UTF-8 *.java
```

The `-encoding UTF-8` flag is required on Windows where the default encoding is Windows-1252, which cannot represent some characters in source files.

### Run (Basic — no blocking)

```bash
java Main ..\test_dpi.pcap ..\output_java.pcap
```

### Run (With command-line blocking rules)

```bash
java Main ..\test_dpi.pcap ..\output_java.pcap --block-app YOUTUBE --block-domain facebook --block-ip 192.168.1.50
```

### Run (With rules.txt — recommended)

```bash
java Main ..\test_dpi.pcap ..\output_java.pcap
```

Rules are automatically loaded from `rules.txt` in the parent directory. Command-line args are applied on top of file rules.

### Regenerate Test Data

```bash
cd DpiEngine
python generate_test_pcap.py
```

Output:
```
Created test_dpi.pcap with test traffic
  - 16 TLS connections with SNI
  - 2 HTTP connections
  - 4 DNS queries
  - 5 packets from blocked IP 192.168.1.50
```

### Verify Output

Open `output_java.pcap` in **Wireshark** to visually verify that blocked traffic is absent from the output. You should see TLS Client Hellos for allowed domains but not for blocked ones.

---

## 10. Rules Configuration

Rules are loaded from `rules.txt` in the DpiEngine root folder. The format is simple:

```
# This is a comment - lines starting with # are ignored
# Blank lines are also ignored

# Block by application type
block-app YOUTUBE
block-app NETFLIX
block-app TIKTOK

# Block by domain keyword (substring match, case-insensitive)
block-domain facebook
block-domain instagram
block-domain twitter

# Block by source IP address (exact match)
block-ip 192.168.1.50
block-ip 10.0.0.5
```

### Available App Names for `block-app`

```
YOUTUBE    FACEBOOK   GOOGLE     NETFLIX    TWITTER
INSTAGRAM  TIKTOK     GITHUB     WHATSAPP   DISCORD
ZOOM       TELEGRAM   SPOTIFY    AMAZON     MICROSOFT
APPLE      CLOUDFLARE HTTP       HTTPS      DNS
```

### Rules Priority

Rules are evaluated in this order for every packet:
1. Source IP check (fastest — HashSet lookup)
2. App type check (HashSet lookup)
3. Domain substring check (linear scan of blocked domains list)

---

## 11. Understanding the Output

### Sample Output (with blocking rules active)

```
==========================================
       DPI ENGINE - Java Version
==========================================
[Rules] Blocking App: YOUTUBE
[Rules] Blocking App: TIKTOK
[Rules] Blocking Domain: facebook
[Rules] Blocking IP: 192.168.1.50

==========================================
            PROCESSING REPORT
==========================================
  Total Packets : 77
  TCP Packets   : 73
  UDP Packets   : 4
------------------------------------------
  Forwarded     : 64
  Dropped       : 13
------------------------------------------
  APPLICATION BREAKDOWN
------------------------------------------
  HTTPS                  : 35
  UNKNOWN                : 18
  DNS                    : 4
  HTTP                   : 2
  GOOGLE                 : 1
  NETFLIX                : 1
  TWITTER                : 1
  INSTAGRAM              : 1
  GITHUB                 : 1
  YOUTUBE (BLOCKED)      : 1
  FACEBOOK (BLOCKED)     : 1
  TIKTOK (BLOCKED)       : 1
------------------------------------------
  DETECTED DOMAINS / SNIs
------------------------------------------
  www.google.com                 -> GOOGLE
  www.youtube.com                -> YOUTUBE
  www.facebook.com               -> FACEBOOK
  www.instagram.com              -> INSTAGRAM
  twitter.com                    -> TWITTER
  www.amazon.com                 -> AMAZON
  www.netflix.com                -> NETFLIX
  github.com                     -> GITHUB
  discord.com                    -> DISCORD
  zoom.us                        -> ZOOM
  web.telegram.org               -> TELEGRAM
  www.tiktok.com                 -> TIKTOK
  open.spotify.com               -> SPOTIFY
  www.cloudflare.com             -> CLOUDFLARE
  www.microsoft.com              -> MICROSOFT
  www.apple.com                  -> APPLE
  example.com                    -> UNKNOWN
  httpbin.org                    -> UNKNOWN
==========================================

[Flow Table] Total flows tracked: 27
[Flow Table] Identified: 18  Blocked: 8
[Done] Output written to: ..\output_java.pcap
```

### What Each Section Means

| Section | Meaning |
|---|---|
| Rules loaded | Which blocking rules are active |
| Total Packets | Packets read from input .pcap |
| TCP / UDP | Protocol breakdown |
| Forwarded | Packets written to output .pcap |
| Dropped | Packets blocked (not in output) |
| Application Breakdown | How many packets per app type |
| Detected SNIs | All domain names the engine found |
| Flow Table | Total connections tracked, how many identified/blocked |

### Why UNKNOWN is High

Packets show as UNKNOWN when:
- They are TCP SYN / ACK packets with no payload (before the Client Hello)
- They belong to a protocol we don't recognize
- The SNI was not in the first payload packet we captured

---

## 12. Extending the Project

### Add a New Application

In `AppType.java`:
```java
public enum AppType {
    // ... existing values
    REDDIT,   // add here
    LINKEDIN  // add here
}
```

In `Main.java` inside `classifyFromSni()`:
```java
if (s.contains("reddit"))   return AppType.REDDIT;
if (s.contains("linkedin")) return AppType.LINKEDIN;
```

### Add a New Rule Type (e.g., block by destination port)

In `RuleManager.java`:
```java
private final Set<Integer> blockedPorts = new HashSet<>();

public void blockPort(int port) {
    blockedPorts.add(port);
}

// Add to shouldBlock():
if (blockedPorts.contains(pkt.dstPort)) return true;
```

In `rules.txt`:
```
block-port 8080
block-port 8443
```

### Add Packet Statistics (bytes transferred per app)

In `Main.java`:
```java
Map<AppType, Long> appBytes = new HashMap<>();

// In the processing loop:
appBytes.merge(pkt.appType, (long) pkt.rawData.length, Long::sum);

// In the report:
appBytes.forEach((app, bytes) ->
    System.out.printf("  %-14s : %d bytes%n", app, bytes));
```

### Scope of Improvement

The version processes packets sequentially. Another version which I will try to implement will be with the help of **Load Balancers** and using **Multi Threading** concurrently. 

Will be updating the architecture and rough Idea shortly.

---

## Summary


The key insight the project demonstrates: **even HTTPS traffic leaks the destination domain name** in the TLS Client Hello. A network operator with access to traffic (ISP, enterprise gateway, router) can identify and block specific applications without breaking encryption, they just read the SNI field before the encryption begins.

---

*It is Built in pure Java SE. No external libraries. No native dependencies.*
*Compatible with any standard .pcap file captured by Wireshark, tcpdump, or similar tools.*