# DPIEngine

A Deep Packet Inspection (DPI) engine built entirely in pure Java.

This project reads raw `.pcap` files, parses network packets layer-by-layer, extracts TLS Server Name Indication (SNI), tracks network flows, classifies applications, and applies custom filtering rules.

Unlike many DPI projects that rely on external packet libraries, this implementation performs packet parsing manually to demonstrate a deep understanding of:

- PCAP format
- Ethernet frames
- IPv4 packets
- TCP/UDP segments
- TLS Client Hello parsing
- SNI extraction
- Flow tracking
- Rule-based traffic filtering

---

## Why This Project?

Most packet inspection tools hide the interesting networking details behind libraries.

This project intentionally takes the opposite approach.

Instead of:

```java
packet.get(IpV4Packet.class)
```

we manually:

- Read packet bytes
- Parse Ethernet headers
- Parse IP headers
- Parse TCP headers
- Navigate TLS structures
- Extract domain names from Client Hello packets

The goal is not only to build a DPI engine, but to understand exactly how modern network inspection systems work internally.

---

# Architecture

```text
PCAP File
    │
    ▼
PcapReader
    │
    ▼
PacketParser
    │
    ▼
ParsedPacket
    │
    ├──────────────► FlowTracker
    │                     │
    │                     ▼
    │                FlowState
    │
    ▼
SniExtractor
    │
    ▼
Application Classification
    │
    ▼
RuleManager
    │
    ▼
ALLOW / BLOCK
```

---

# Features

### PCAP Parsing

- Reads standard `.pcap` files
- Parses global headers
- Parses per-packet headers
- Supports Ethernet traffic

### Packet Parsing

Parses:

- Ethernet
- IPv4
- TCP
- UDP

Extracts:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol
- Payload

### TLS Inspection

Inspects TLS Client Hello packets.

Extracts:

- SNI Extension
- Domain Name

Example:

```text
www.youtube.com
github.com
www.facebook.com
```

### Flow Tracking

Tracks traffic using a Five Tuple:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

Example:

```text
192.168.1.10:53421
        ↓
142.250.183.14:443
        ↓
TCP
```

### Application Classification

Maps domains to applications.

Examples:

```text
youtube.com   → YOUTUBE
facebook.com  → FACEBOOK
github.com    → GITHUB
```

### Rule Engine

Supports:

- Block by IP
- Block by Domain
- Block by Application

Example:

```java
rules.blockDomain("youtube");
rules.blockApp(AppType.FACEBOOK);
rules.blockIp("192.168.1.100");
```

---

# Project Structure

```text
DPIEngine
│
├── src
│   ├── Main.java
│   ├── PcapReader.java
│   ├── PacketParser.java
│   ├── SniExtractor.java
│   ├── RuleManager.java
│   ├── FlowTracker.java
│   ├── FiveTuple.java
│   ├── FlowState.java
│   ├── AppType.java
│   ├── ParsedPacket.java
│
├── test_dpi.pcap
└── README.md
```

---

# Core Concepts Implemented

## Ethernet Parsing

Reads:

```text
Destination MAC
Source MAC
EtherType
```

Example:

```text
AA:BB:CC:DD:EE:FF
```

---

## IPv4 Parsing

Extracts:

```text
Version
Header Length
Protocol
Source IP
Destination IP
```

Example:

```text
192.168.1.100
172.217.14.206
```

---

## TCP Parsing

Extracts:

```text
Source Port
Destination Port
Header Length
Payload Offset
```

Example:

```text
54321 → 443
```

---

## TLS Parsing

Navigates:

```text
TLS Record
    └── Client Hello
            └── Extensions
                    └── SNI
```

Example:

```text
SNI = www.youtube.com
```

---

# Flow Tracking

Each connection is represented by:

```java
(srcIP, dstIP, srcPort, dstPort, protocol)
```

Stored inside:

```java
HashMap<FiveTuple, FlowState>
```

This allows:

- Session tracking
- Application persistence
- Fast rule evaluation

---

# Example Execution

Input:

```text
User opens YouTube
```

Traffic:

```text
TLS Client Hello
SNI = www.youtube.com
```

Processing:

```text
PCAP Reader
    ↓
Packet Parser
    ↓
SNI Extractor
    ↓
App Detection
    ↓
Rule Manager
```

Output:

```text
[YOUTUBE] www.youtube.com
ACTION: BLOCKED
```

---

# Learning Outcomes

This project demonstrates understanding of:

### Networking

- TCP/IP Stack
- Ethernet
- IPv4
- TCP
- UDP
- TLS

### Security

- Deep Packet Inspection
- Traffic Classification
- Domain Filtering
- Flow Analysis

### Java

- Binary Parsing
- File I/O
- Collections
- HashMap
- Enums
- Object-Oriented Design

### Systems Design

- Packet Pipelines
- Flow State Management
- Rule Engines
- Protocol Parsing

---

# Future Improvements

### IPv6 Support

Current:

```text
IPv4 Only
```

Future:

```text
IPv4 + IPv6
```

---

### DNS Classification

Extract domains from:

```text
DNS Queries
```

in addition to TLS SNI.

---

### Multi-threaded Pipeline

```text
Capture Thread
      ↓
Thread-Safe Queue
      ↓
Parser Thread
      ↓
Classification Thread
```

---

### PCAP Writer

Generate:

```text
filtered_output.pcap
```

containing only allowed traffic.

---

### Reporting Dashboard

Generate statistics:

```text
Top Domains
Top Applications
Blocked Traffic
Flow Counts
Bandwidth Usage
```

---

# Example Use Cases

- Learning packet parsing
- Understanding TLS internals
- Network traffic analysis
- Security research
- Academic projects
- Interview demonstrations
- Portfolio projects

---

# Key Takeaway

This project intentionally avoids packet parsing libraries and performs protocol analysis manually.

The objective is not simply to inspect packets, but to understand every byte between:

```text
Raw PCAP Bytes
          ↓
Ethernet
          ↓
IPv4
          ↓
TCP
          ↓
TLS Client Hello
          ↓
SNI
          ↓
Application
          ↓
Policy Decision
```

Building a DPI engine from scratch provides hands-on experience with the same foundational concepts used in modern firewalls, IDS/IPS systems, packet analyzers, and network security products.
