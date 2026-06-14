# DPI Engine - Deep Packet Inspection System
 
Ever tried opening a website only to find that it was blocked by your ISP, company network, college Wi-Fi, or even a government firewall?
 
How does a network know you're visiting YouTube, Facebook, Netflix, or Discord when the traffic is protected by HTTPS encryption?
 
The answer lies in **Deep Packet Inspection (DPI)**.
 
To understand how modern network filtering works, I built a complete DPI Engine from scratch in Java. The system reads raw packet captures, parses Ethernet/IP/TCP layers, extracts TLS SNI information from HTTPS handshakes, classifies applications, tracks flows, and applies real-world blocking rules exactly like a simplified network firewall.
 
Two versions are implemented:
- **Simple Version** — single-threaded, sequential processing (`Main.java`)
- **Multi-threaded Version** — Load Balancer + Fast Path architecture (`DpiEngine.java`)
**Not interested in the contents and want to test it yourself directly?**
[Click Here](#9-building-and-running) to navigate to building and running commands.
 
---
 
## Table of Contents
 
1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet — Simple Version](#5-the-journey-of-a-packet--simple-version)
6. [The Journey of a Packet — Multi-threaded Version](#6-the-journey-of-a-packet--multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Rules Configuration](#11-rules-configuration)
12. [Understanding the Output](#12-understanding-the-output)
13. [Extending the Project](#13-extending-the-project)
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
generate_test_pcap.py        DPI Engine (Java)           output.pcap
+---------------------+      +----------------------+     +---------------+
| Creates test PCAP   |      | PcapReader.java      |     | Allowed       |
| with:               | ---> | PacketParser.java    | --> | packets only  |
| - TLS connections   |      | SniExtractor.java    |     | (blocked ones |
| - HTTP traffic      |      | FlowTracker.java     |     |  dropped)     |
| - DNS queries       |      | RuleManager.java     |     +---------------+
| - Blocked IPs       |      | Main.java / DpiEngine|
+---------------------+      +----------------------+
                                       |
                              rules.txt (config)
                              block-app YOUTUBE
                              block-domain facebook
                              block-ip 192.168.1.50
```
 
### Two Versions
 
| Version | Entry Point | Design | Use Case |
|---|---|---|---|
| Simple | `Main.java` | Single-threaded, sequential | Learning, small captures |
| Multi-threaded | `DpiEngine.java` | LB + Fast Path threads | Large captures, production-like |
 
### Design Philosophy
 
The simple version is **single-threaded and file-based** — reads packets sequentially, processes one at a time. It is easy to understand, debug, and sufficient for moderate-sized captures.
 
The multi-threaded version mirrors how **real production DPI engines** are built — separate threads for reading, load balancing, packet processing, and writing. The same five-tuple always goes to the same processing thread, eliminating the need for locks on flow state.
 
Both versions are **zero external dependencies** — pure Java SE.
 
---
 
## 4. File Structure
 
```
DpiEngine/
|
+-- src/                          <- All Java source files
|   |
|   | -- SHARED (used by both versions) --
|   +-- AppType.java              <- Enum: YOUTUBE, FACEBOOK, DNS, etc.
|   +-- FiveTuple.java            <- Connection key (5-tuple with hashCode/equals)
|   +-- ParsedPacket.java         <- Data holder for one parsed packet
|   +-- FlowState.java            <- Per-connection state (SNI seen? blocked?)
|   +-- PcapReader.java           <- Reads binary .pcap file format
|   +-- PacketParser.java         <- Ethernet / IP / TCP / UDP header parsing
|   +-- SniExtractor.java         <- TLS Client Hello -> domain name
|   +-- RuleManager.java          <- Blocking rules: IP / app / domain
|   +-- FlowTracker.java          <- HashMap-based flow table (simple version)
|   |
|   | -- SIMPLE VERSION --
|   +-- Main.java                 <- Single-threaded orchestrator + report
|   |
|   | -- MULTI-THREADED VERSION --
|   +-- RawPacket.java            <- Raw bytes wrapper + poison pill sentinel
|   +-- LoadBalancer.java         <- LB thread: routes packets to Fast Paths
|   +-- FastPath.java             <- FP thread: private flow table, parse, classify, block
|   +-- WriterThread.java         <- Writer thread: output PCAP + report
|   +-- DpiEngine.java            <- Multi-threaded main: wires all threads together
|
+-- generate_test_pcap.py         <- Python script to generate test traffic
+-- test_dpi.pcap                 <- Sample capture (77 packets, 18 domains)
+-- rules.txt                     <- Blocking rules config file
+-- output_java.pcap              <- Simple version output (generated on run)
+-- output_mt.pcap                <- Multi-threaded version output (generated on run)
+-- README.md                     <- This file
```
 
### Dependency Graph — Simple Version
 
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
 
### Dependency Graph — Multi-threaded Version
 
```
DpiEngine.java (main thread — reader)
  |-- PcapReader.java           (reads raw bytes)
  |-- RawPacket.java            (queue item + poison pill)
  |-- LoadBalancer.java         (LB threads)
  |     |-- RawPacket.java
  |-- FastPath.java             (FP threads — own private flow table)
  |     |-- PacketParser.java
  |     |-- SniExtractor.java
  |     |-- FiveTuple.java
  |     |-- FlowState.java
  |     |-- RuleManager.java
  |     |-- ParsedPacket.java
  |-- WriterThread.java         (writer thread)
        |-- ParsedPacket.java
```
 
---
 
## 5. The Journey of a Packet — Simple Version
 
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
 
This is the **fast path** — once a flow is identified and blocked, all subsequent packets of that flow are dropped immediately without any further parsing.
 
---
 
### Step 5: Extract SNI (`SniExtractor.java`)
 
```java
String sni = SniExtractor.extractSni(pkt.payload);
 
// Fallback for unencrypted HTTP:
if (sni == null) sni = SniExtractor.extractHttpHost(pkt.payload);
```
 
This is the core DPI step — detailed in [Section 8](#8-how-sni-extraction-works).
 
---
 
### Step 6: Classify the Application
 
```java
AppType app = classifyFromSni(sni);
// "www.youtube.com"  -> AppType.YOUTUBE
// "www.facebook.com" -> AppType.FACEBOOK
// "discord.com"      -> AppType.DISCORD
```
 
Classification uses simple substring matching:
 
```java
if (s.contains("youtube") || s.contains("googlevideo")) return AppType.YOUTUBE;
if (s.contains("facebook") || s.contains("fbcdn"))      return AppType.FACEBOOK;
if (s.contains("netflix"))                               return AppType.NETFLIX;
// ... 17 more patterns
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
 
When a flow is marked blocked, **all future packets** of that connection are dropped in Step 4 without re-checking rules.
 
---
 
## 6. The Journey of a Packet — Multi-threaded Version
 
The multi-threaded version adds **parallelism** for high performance. Multiple threads work simultaneously: one reads, two load-balance, four process, one writes.
 
### Architecture Overview
 
```
                    +------------------+
                    |   Reader Thread  |
                    |   (main thread)  |
                    |   reads PCAP     |
                    +--------+---------+
                             |
                             | round-robin distribution
              +--------------+--------------+
              |                             |
              v                             v
    +------------------+         +------------------+
    |   LB0 Thread     |         |   LB1 Thread     |
    |  (Load Balancer) |         |  (Load Balancer) |
    +--------+---------+         +--------+---------+
             |                            |
             | hash(5-tuple) % 2          | hash(5-tuple) % 2
      +-------+-------+            +------+------+
      v               v            v             v
+----------+   +----------+  +----------+  +----------+
| FP0      |   | FP1      |  | FP2      |  | FP3      |
| FastPath |   | FastPath |  | FastPath |  | FastPath |
| private  |   | private  |  | private  |  | private  |
| flow tbl |   | flow tbl |  | flow tbl |  | flow tbl |
+----+-----+   +----+-----+  +----+-----+  +----+-----+
     |               |            |              |
     +---------------+------------+--------------+
                          |
                          v
                 +------------------+
                 |   Output Queue   |
                 | (BlockingQueue)  |
                 +--------+---------+
                          |
                          v
                 +------------------+
                 |  Writer Thread   |
                 |  writes PCAP +   |
                 |  prints report   |
                 +------------------+
```
 
### Why This Design?
 
**Consistent hashing** is the key idea. The same five-tuple always hashes to the same Fast Path thread:
 
```
Connection: 192.168.1.100:54321 -> 142.250.185.110:443
 
Packet 1 (SYN):          hash -> FP2
Packet 2 (SYN-ACK):      hash -> FP2  (same FP!)
Packet 3 (ACK):           hash -> FP2  (same FP!)
Packet 4 (Client Hello):  hash -> FP2  (same FP!)
Packet 5 (data):          hash -> FP2  (same FP!)
```
 
Because all packets of a connection go to the same FP, each FP can use a **plain private `HashMap`** for its flow table — no locking, no `ConcurrentHashMap`, no synchronization needed. This is both simpler and faster.
 
### Thread Roles
 
| Thread | Class | Count | Responsibility |
|---|---|---|---|
| Reader | `DpiEngine.java` (main) | 1 | Reads PCAP, feeds LB queues |
| Load Balancer | `LoadBalancer.java` | 2 | Routes packets to FPs by hash |
| Fast Path | `FastPath.java` | 4 | Parse, classify, block, forward |
| Writer | `WriterThread.java` | 1 | Write output PCAP + print report |
 
### The Poison Pill Shutdown Pattern
 
When the reader finishes, it cannot just stop the threads abruptly — workers may still have items to process. Instead it uses a **poison pill**: a special sentinel object placed in the queue that signals "no more work".
 
```
Reader finishes PCAP
  -> sends 1 poison pill to each LB queue
 
Each LB receives poison pill
  -> forwards 1 poison pill to each of its FP queues
  -> then exits
 
Each FP receives poison pill
  -> sends 1 poison pill to output queue (signals Writer)
  -> then exits
 
Writer counts poison pills received (one per FP)
  -> when all FPs done: flush output, print report, exit
```
 
```java
// RawPacket.java
public static RawPacket poisonPill() {
    RawPacket r = new RawPacket();
    r.isPoisonPill = true;
    return r;
}
 
// Writer detects FP shutdown via null rawData:
if (pkt.rawData == null) {
    poisonPillsReceived++;
    if (poisonPillsReceived == numFPs) break; // all FPs done
}
```
 
### Queue Backpressure
 
All queues are **bounded** (`LinkedBlockingQueue` with a capacity limit). If a downstream thread is slow, the upstream thread blocks on `put()` instead of flooding memory:
 
```java
// LB input queue: max 1000 items
inputQueue = new LinkedBlockingQueue<>(1000);
 
// If LB is slow, reader blocks here until space is available
lbs[lbIdx].getInputQueue().put(raw);
```
 
### Simple vs Multi-threaded: Key Differences
 
| Aspect | Simple (`Main.java`) | Multi-threaded (`DpiEngine.java`) |
|---|---|---|
| Threads | 1 | 8 (1 reader + 2 LB + 4 FP + 1 writer) |
| Flow table | 1 shared `HashMap` | 4 private `HashMap`s (one per FP) |
| Locking needed | No | No (private tables + atomic counters) |
| Throughput | Sequential | Parallel |
| Best for | Learning, small files | Large captures, benchmarking |
 
---
 
## 7. Deep Dive: Each Component
 
### `AppType.java`
 
Enum listing every application the engine can recognize:
 
```java
public enum AppType {
    UNKNOWN, HTTP, HTTPS, DNS,
    YOUTUBE, FACEBOOK, GOOGLE, NETFLIX,
    TWITTER, INSTAGRAM, TIKTOK, GITHUB,
    WHATSAPP, DISCORD, ZOOM, TELEGRAM,
    SPOTIFY, AMAZON, MICROSOFT, APPLE, CLOUDFLARE
}
```
 
Every `ParsedPacket` and `FlowState` carries an `AppType`. It starts as `UNKNOWN` and gets upgraded once SNI is extracted or a port match is found.
 
---
 
### `FiveTuple.java`
 
Connection identifier used as the `HashMap` key. Must override `hashCode()` and `equals()` correctly — if two `FiveTuple` objects represent the same connection, they must return the same hash and be equal.
 
Normalization ensures both directions of a connection share the same key:
 
```java
boolean flip = srcIp.compareTo(dstIp) > 0 ||
               (srcIp.equals(dstIp) && srcPort > dstPort);
```
 
---
 
### `ParsedPacket.java`
 
Plain data class holding everything extracted from one packet. No logic — just fields:
 
```
rawData[], timestampSec, timestampUsec   <- PCAP level
srcMac, dstMac, etherType               <- Ethernet level
srcIp, dstIp, protocol, ipHeaderLen     <- IP level
srcPort, dstPort, isTcp, isUdp          <- TCP/UDP level
payload[], payloadOffset                <- Application data
sni, appType, blocked                   <- After classification
```
 
---
 
### `FlowState.java`
 
Per-connection state. One instance exists per unique five-tuple in the flow table:
 
```java
AppType appType = AppType.UNKNOWN;  // what app is this flow?
String  sni     = null;             // domain name once seen
boolean blocked = false;            // drop all future packets?
boolean sniSeen = false;            // stop trying to extract SNI?
```
 
Once `sniSeen = true`, SNI extraction is skipped for all future packets of that flow. Once `blocked = true`, all future packets are dropped instantly.
 
---
 
### `PcapReader.java`
 
Reads the binary `.pcap` file format using `FileInputStream`. Handles both little-endian and big-endian files by detecting the magic number. Returns one packet at a time via `readNextPacket()`.
 
---
 
### `PacketParser.java`
 
Static class. Takes `pkt.rawData` and fills all `ParsedPacket` fields by reading byte offsets according to protocol specs. Handles variable-length IP and TCP headers via IHL and Data Offset fields.
 
---
 
### `SniExtractor.java`
 
Two static methods:
- `extractSni(byte[] payload)` — navigates TLS Client Hello binary structure, returns domain or null
- `extractHttpHost(byte[] payload)` — reads `Host:` header from HTTP request, returns domain or null
See [Section 8](#8-how-sni-extraction-works) for full byte-level walkthrough.
 
---
 
### `RuleManager.java`
 
Stores three `HashSet`s and evaluates them against each packet:
 
```java
Set<String>   blockedIps;      // exact IP match   -> O(1)
Set<AppType>  blockedApps;     // exact enum match  -> O(1)
Set<String>   blockedDomains;  // substring match   -> O(n)
```
 
Two check methods:
- `shouldBlock(ParsedPacket pkt)` — for current packet fields
- `shouldBlockFlow(FlowState flow)` — for packets after the Client Hello (uses stored flow classification)
---
 
### `FlowTracker.java`
 
Wraps a `HashMap<FiveTuple, FlowState>` with helper methods:
 
```java
public FlowState getOrCreate(FiveTuple key) {
    return table.computeIfAbsent(key, k -> new FlowState());
}
```
 
Used only by the simple version. The multi-threaded version has each `FastPath` manage its own private `HashMap` directly.
 
---
 
### `RawPacket.java` *(multi-threaded only)*
 
Minimal wrapper passed through LB → FP queues. Contains only raw bytes and timestamp — no parsing yet:
 
```java
public class RawPacket {
    public byte[] data;
    public long   timestampSec;
    public long   timestampUsec;
    public boolean isPoisonPill;
 
    public static RawPacket poisonPill() { ... }
}
```
 
Keeping it raw (unparsed) is important — parsing happens inside the FP threads in parallel, not in the reader thread.
 
---
 
### `LoadBalancer.java` *(multi-threaded only)*
 
Each LB thread:
1. Takes packets from its `inputQueue` (blocking `take()`)
2. Hashes raw bytes at IP + port offsets to select an FP
3. Puts packet into that FP's queue
```java
// Hash IP + port bytes directly from raw data
// Ethernet=14 bytes, IP src starts at byte 26
int hash = 0;
hash ^= (data[26] & 0xFF) << 24;  // src IP byte 1
hash ^= (data[27] & 0xFF) << 16;  // src IP byte 2
// ... dst IP and ports
return Math.abs(hash) % numFPs;
```
 
Hashing raw bytes (before parsing) avoids the overhead of full packet parsing in the LB thread — LBs just route, FPs do the real work.
 
---
 
### `FastPath.java` *(multi-threaded only)*
 
The core processing thread. Each FP has its **own private `HashMap<FiveTuple, FlowState>`** — no other thread ever touches it. Processing steps mirror the simple version exactly:
 
```
take packet from inputQueue
  -> parse headers (PacketParser)
  -> look up / create flow in private HashMap
  -> if flow.blocked: droppedPackets.incrementAndGet() -> discard
  -> extract SNI (SniExtractor)
  -> classify app
  -> check rules (RuleManager)
  -> if blocked: mark flow, droppedPackets++
  -> else: forwardedPackets++, put to outputQueue
```
 
Shared counters (`AtomicInteger`) are used for stats so all FPs can increment them safely:
 
```java
droppedPackets.incrementAndGet();   // thread-safe increment
forwardedPackets.incrementAndGet();
```
 
---
 
### `WriterThread.java` *(multi-threaded only)*
 
Drains the output queue and writes forwarded packets to the output PCAP. Waits for exactly `numFPs` poison pills before printing the report and exiting:
 
```java
int poisonPillsReceived = 0;
while (poisonPillsReceived < numFPs) {
    ParsedPacket pkt = outputQueue.take();
    if (pkt.rawData == null) { poisonPillsReceived++; continue; }
    Main.writePacket(out, pkt);  // reuses the PCAP writer from simple version
}
printReport();
```
 
---
 
### `Main.java` *(simple version)*
 
The orchestrator for the single-threaded version. Also contains two static utility methods reused by the multi-threaded version:
- `writePcapGlobalHeader(OutputStream out)` — writes the 24-byte PCAP file header
- `writePacket(OutputStream out, ParsedPacket pkt)` — writes one packet with its 16-byte header
- `loadRulesFromFile(String filename, RuleManager rules)` — parses `rules.txt`
---
 
### `DpiEngine.java` *(multi-threaded version)*
 
The entry point for the multi-threaded version. Responsibilities:
1. Parse command-line args and load `rules.txt`
2. Create FP queues (`LinkedBlockingQueue[]`)
3. Create and start FP threads
4. Create and start LB threads (each gets a slice of FP queues)
5. Create and start Writer thread
6. Read PCAP in main thread, distribute to LBs round-robin
7. Send poison pills to all LBs
8. `join()` all threads and exit
Also contains `classifyFromSni()` and `classifyFromPort()` as public static methods so `FastPath` threads can call them.
 
---
 
## 8. How SNI Extraction Works
 
### The TLS Handshake Timeline
 
```
Browser                                    YouTube Server
  |                                              |
  |------- TCP SYN --------------------------->  |
  |<------ TCP SYN-ACK ------------------------  |
  |------- TCP ACK --------------------------->  |
  |                                              |
  |------- TLS Client Hello ------------------>  |  <- WE READ THIS
  |        [SNI: "www.youtube.com" PLAINTEXT]    |
  |                                              |
  |<------ TLS Server Hello -------------------  |
  |        [certificate, cipher choice]          |
  |                                              |
  |<============ Encrypted from here on ======>  |
  |   (we cannot read anything past this point)  |
```
 
### TLS Client Hello Byte Layout
 
```
TCP Payload bytes:
 
[0]      0x16          <- Content Type: Handshake
[1]      0x03          <- TLS Major Version
[2]      0x01/03       <- TLS Minor Version
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
 
## 9. How Blocking Works
 
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
Connection to YouTube (192.168.1.100:54321 -> 142.250.185.110:443):
 
Packet 1: TCP SYN         -> no payload, no SNI -> FORWARD
Packet 2: TCP SYN-ACK     -> no payload, no SNI -> FORWARD
Packet 3: TCP ACK         -> no payload, no SNI -> FORWARD
Packet 4: TLS ClientHello -> SNI: www.youtube.com -> AppType: YOUTUBE
                          -> YOUTUBE is in blockedApps
                          -> flow.blocked = true -> DROP
Packet 5: TLS data        -> flow.blocked == true -> DROP (fast path)
Packet 6: TLS data        -> flow.blocked == true -> DROP (fast path)
...all remaining packets  -> DROP (fast path)
```
 
**Why do packets 1-3 get forwarded?** We have no information yet about what application this connection belongs to. The Client Hello (packet 4) is the first packet that contains the SNI. In a real inline DPI system, those early packets could be buffered and dropped retroactively, but for this file-based implementation they are forwarded.
 
---
 
## 10. Building and Running
 
### Prerequisites
 
- **Java SE 8 or higher** (uses `java.util`, `java.io` only — no external dependencies)
- **Python 3** (only needed to regenerate test data)
- **Windows / Linux / macOS** (platform independent)
### Compile
 
```bash
cd DpiEngine/src
javac -encoding UTF-8 *.java
```
 
The `-encoding UTF-8` flag is required on Windows where the default encoding is Windows-1252.
 
This compiles **all files** — both simple and multi-threaded versions together.
 
---
 
### Simple Version — `Main.java`
 
**Basic run (no blocking):**
```bash
java Main ..\test_dpi.pcap ..\output_java.pcap
```
 
**With command-line blocking rules:**
```bash
java Main ..\test_dpi.pcap ..\output_java.pcap --block-app YOUTUBE --block-domain facebook --block-ip 192.168.1.50
```
 
**With rules.txt (recommended):**
```bash
java Main ..\test_dpi.pcap ..\output_java.pcap
```
Rules are automatically loaded from `rules.txt` in the parent directory. Command-line args add on top.
 
---
 
### Multi-threaded Version — `DpiEngine.java`
 
**Basic run (default: 2 LBs, 4 FPs):**
```bash
java DpiEngine ..\test_dpi.pcap ..\output_mt.pcap
```
 
**With custom thread counts:**
```bash
java DpiEngine ..\test_dpi.pcap ..\output_mt.pcap --lbs 2 --fps 4
```
 
**With blocking rules:**
```bash
java DpiEngine ..\test_dpi.pcap ..\output_mt.pcap --block-app YOUTUBE --block-domain facebook
```
 
**All options:**
 
| Flag | Example | Effect |
|---|---|---|
| `--block-ip` | `--block-ip 192.168.1.50` | Block all traffic from this IP |
| `--block-app` | `--block-app YOUTUBE` | Block all flows of this app type |
| `--block-domain` | `--block-domain tiktok` | Block any SNI containing this keyword |
| `--lbs` | `--lbs 2` | Number of Load Balancer threads |
| `--fps` | `--fps 4` | Number of Fast Path threads |
 
---
 
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
 
Open either output PCAP in **Wireshark** to visually verify that blocked traffic is absent. You should see TLS Client Hellos for allowed domains but not for blocked ones.
 
---
 
## 11. Rules Configuration
 
Rules are loaded from `rules.txt` in the DpiEngine root folder:
 
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
1. Source IP check (fastest — `HashSet` lookup, O(1))
2. App type check (`HashSet` lookup, O(1))
3. Domain substring check (linear scan, O(n domains))
---
 
## 12. Understanding the Output
 
### Simple Version Output
 
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
  YOUTUBE (BLOCKED)      : 1
  FACEBOOK (BLOCKED)     : 1
  TIKTOK (BLOCKED)       : 1
------------------------------------------
  DETECTED DOMAINS / SNIs
------------------------------------------
  www.google.com                 -> GOOGLE
  www.youtube.com                -> YOUTUBE
  www.facebook.com               -> FACEBOOK
  ...
==========================================
[Flow Table] Total flows tracked: 27
[Flow Table] Identified: 18  Blocked: 8
[Done] Output written to: ..\output_java.pcap
```
 
### Multi-threaded Version Output
 
```
==========================================
   DPI ENGINE - Multi-threaded Java
   Load Balancers : 2
   Fast Paths     : 4
==========================================
 
[LB0] Started
[LB1] Started
[FP0] Started
[FP1] Started
[FP2] Started
[FP3] Started
[Writer] Started
[Reader] Done. Sent 77 packets.
[LB0] Received poison pill, shutting down
[LB1] Received poison pill, shutting down
[FP0] Received poison pill, shutting down
[FP1] Received poison pill, shutting down
[FP2] Received poison pill, shutting down
[FP3] Received poison pill, shutting down
[Writer] FP done signal 1/4
[Writer] FP done signal 2/4
[Writer] FP done signal 3/4
[Writer] FP done signal 4/4
 
==========================================
     DPI ENGINE - Multi-threaded Java
==========================================
  Total Packets : 77
------------------------------------------
  Forwarded     : 64
  Dropped       : 13
------------------------------------------
  APPLICATION BREAKDOWN
  ...
==========================================
[DpiEngine] All threads stopped.
```
 
### What Each Section Means
 
| Section | Meaning |
|---|---|
| Rules loaded | Which blocking rules are active |
| Total Packets | Packets read from input .pcap |
| TCP / UDP | Protocol breakdown (simple version) |
| Forwarded | Packets written to output .pcap |
| Dropped | Packets blocked (not in output) |
| Application Breakdown | How many packets per app type |
| Detected SNIs | All domain names the engine found |
| Flow Table | Total connections tracked (simple version) |
| Thread logs | Startup/shutdown of each thread (multi-threaded) |
 
### Why UNKNOWN is High
 
Packets show as UNKNOWN when:
- They are TCP SYN / ACK packets with no payload (before the Client Hello)
- They belong to a protocol we don't recognize
- The SNI was not in the first payload packet captured
---
 
## 13. Extending the Project
 
### Add a New Application
 
In `AppType.java`:
```java
public enum AppType {
    // ... existing values
    REDDIT,
    LINKEDIN
}
```
 
In `Main.java` and `DpiEngine.java` inside `classifyFromSni()`:
```java
if (s.contains("reddit"))   return AppType.REDDIT;
if (s.contains("linkedin")) return AppType.LINKEDIN;
```
 
### Add a New Rule Type (e.g., block by destination port)
 
In `RuleManager.java`:
```java
private final Set<Integer> blockedPorts = new HashSet<>();
 
public void blockPort(int port) { blockedPorts.add(port); }
 
// Add to shouldBlock():
if (blockedPorts.contains(pkt.dstPort)) return true;
```
 
In `rules.txt`:
```
block-port 8080
block-port 8443
```
 
### Add Packet Statistics (bytes per app)
 
In `Main.java`:
```java
Map<AppType, Long> appBytes = new HashMap<>();
 
// In the processing loop:
appBytes.merge(pkt.appType, (long) pkt.rawData.length, Long::sum);
 
// In the report:
appBytes.forEach((app, bytes) ->
    System.out.printf("  %-14s : %d bytes%n", app, bytes));
```
 
### Scale the Multi-threaded Version
 
Try different thread counts on a large PCAP file:
 
```bash
java DpiEngine large_capture.pcap output.pcap --lbs 4 --fps 8
```
 
More FPs help when packet processing (SNI extraction, rule checks) is the bottleneck. More LBs help when routing itself becomes a bottleneck at very high packet rates.
 
### Add DNS Query Parsing
 
Currently DNS packets are classified by port (53) but the queried domain is not extracted. DNS uses label encoding:
 
```
Query for "www.google.com":
[3] w w w [6] g o o g l e [3] c o m [0]
 ^len      ^label          ^label    ^end
```
 
A `DnsParser.java` could extract the queried domain from UDP port 53 payloads and add it to the SNI map.
 
---
 
## Summary
 
| Concept | Where Implemented |
|---|---|
| Binary file I/O | `PcapReader.java` |
| Network protocol parsing | `PacketParser.java` |
| Bitwise operations in Java | `PacketParser.java`, `PcapReader.java` |
| TLS handshake structure | `SniExtractor.java` |
| HashMap-based state tracking | `FlowTracker.java`, `FastPath.java` |
| Flow-level traffic control | `FlowState.java`, `Main.java`, `FastPath.java` |
| Rule-based packet filtering | `RuleManager.java` |
| PCAP file writing | `Main.java` |
| Producer-consumer threading | `LoadBalancer.java`, `FastPath.java`, `WriterThread.java` |
| Poison pill shutdown | `RawPacket.java`, `LoadBalancer.java`, `WriterThread.java` |
| Lock-free flow tables | `FastPath.java` (private `HashMap` per thread) |
| Atomic shared counters | `FastPath.java` (`AtomicInteger`) |
| Bounded queue backpressure | `DpiEngine.java` (`LinkedBlockingQueue` with capacity) |
 
The key insight this project demonstrates: **even HTTPS traffic leaks the destination domain name** in the TLS Client Hello. A network operator with access to traffic (ISP, enterprise gateway, router) can identify and block specific applications without breaking encryption — they just read the SNI field before encryption begins.
 
---
 
*Built in pure Java SE. No external libraries. No native dependencies.*
*Compatible with any standard .pcap file captured by Wireshark, tcpdump, or similar tools.*