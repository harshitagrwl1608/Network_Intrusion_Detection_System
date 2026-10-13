![Embedded
figure](Project_Synopsis_IDS_Software_Formatted_assets/image1.jpeg)

**A Lightweight, Self-Built Network Intrusion Detection System with
Plain-Language Visualization**

Submitted by

**Harshit**

**Roll No.** **25001011018**

Under the mentorship of

**Dr.** **Shivi** **Garg**

**J.C. Bose University of Science & Technology, YMCA**

**TABLE OF CONTENTS**

Table of Contents i

**Chapter 1: Introduction 1**

1.1 Brief of the Project 1

1.2 Technologies Used 2

1.2.1 Packet Capture and Detection 2

1.2.2 Storage and Analysis 2

1.2.3 Dashboard 2

1.2.4 Evaluation 2

**Chapter 2: Proposed Methodology 2**

2.1 System Architecture 2

2.2 Data Design 3

2.3 Core Modules and Workflow 4

2.3.1 Packet Capture 4

2.3.2 Rule Engine 4

2.3.3 Analysis Layer and Dashboard 5

2.4 Development Methodology 5

**Chapter 3: Applications and Scope 6**

3.1 Applications 6

3.2 Future Scope 6

**CHAPTER 1: INTRODUCTION**

**1.1 BRIEF OF THE PROJECT**

Home and small-office networks generate a continuous stream of traffic
and connection activity, almost none of which is ever examined by the
people who own and use those networks. Commercial-grade monitoring tools
exist, but are built for trained IT administrators, not for the
individuals and small businesses who most need basic visibility into
what is happening on their own network. This project builds a small,
self-contained intrusion detection system from first principles, paired
with a dashboard that explains its findings in plain language rather
than technical jargon.

Unlike a design built entirely around installing and configuring
existing security software, this project\'s core detection logic is
written from scratch, so that the process of building it also serves as
a structured, hands-on study of how real intrusion detection systems
work at a fundamental level. The core idea is to capture live network
traffic at a single observation point, examine each packet against a
small set of hand-written detection rules modelled on real attack
patterns, log anything that matches, and translate those technical log
entries into short, plain-English statements displayed on a simple
dashboard.

The project rests on a small set of stated assumptions: the monitoring
device is positioned where it can observe the traffic of interest (via
switch mirroring, a bridged router, or a shared network segment, treated
as an already-addressed infrastructure concern); the system targets a
small network realistically under fifty devices, not enterprise-scale
volumes; detection is signature and threshold-based rather than
Machine-Learning-based, keeping the logic transparent and tunable; the
system is designed to detect and alert rather than actively block
traffic, making it an Intrusion Detection System (IDS) rather than an
Intrusion Prevention System (IPS); and the end user of the dashboard is
assumed to have no networking or security background.

The objectives that follow from this are to: capture live packets and
extract the fields relevant to security analysis; implement hand-written
detection rules covering port scanning, connection-rate abuse, ARP
spoofing, and known-malicious-destination matching; log all matched
events in a structured form; aggregate these events into higher-level,
human-relevant observations; translate these observations into a
plain-language dashboard; and evaluate the system\'s detection accuracy
against a mature reference engine, Suricata, run on the same captured
traffic.

**1.2 TECHNOLOGIES USED**

**1.2.1 Packet Capture and Detection**

Python 3.10+ --- the language used throughout the detection engine and
dashboard.

Scapy --- packet capture and parsing; well-documented and directly
exposes the packet-level fields needed for custom rule-writing.

libpcap --- the underlying system-level capture library Scapy depends on
for live packet capture on Linux.

**1.2.2 Storage and Analysis**

SQLite --- lightweight, zero-configuration, file-based storage for
logged alerts; built into Python\'s standard library.

Pandas (optional) --- convenient aggregation and grouping in the
analysis layer.

A free, publicly available IP blocklist (e.g. abuse.ch-style
threat-intelligence feeds) --- avoids the need to compile a malicious-IP
list manually.

**1.2.3 Dashboard**

Flask or Streamlit --- minimal Python web framework, keeping the whole
stack in one language.

HTML/CSS with a lightweight charting library (Chart.js) --- simple,
framework-free visuals sufficient for a handful of widgets.

**1.2.4 Evaluation**

Suricata --- used only as a reference/comparison engine to evaluate the
custom engine\'s detection accuracy, not as the primary runtime engine.

**CHAPTER 2: PROPOSED METHODOLOGY**

**2.1 SYSTEM ARCHITECTURE**

The diagram below shows where this software component sits within the
broader network setup it is designed for (a small office network, as
established in the accompanying project research). The capture and
detection logic corresponds to the "Raspberry Pi (Capture + Detection
Engine)" block, positioned on a mirrored port so that it observes wired,
Wi-Fi, and internet-bound traffic simultaneously.

![Embedded
figure](Project_Synopsis_IDS_Software_Formatted_assets/image2.png)

*Figure 2.1: System architecture --- placement of the capture and
detection component within the network.*

**2.2 DATA DESIGN**

From each captured packet, only the fields relevant to detection are
extracted and carried forward: source IP address, destination IP
address, destination port, protocol (TCP/UDP/ICMP), and relevant TCP
flags such as the SYN flag used to identify new connection attempts.
This keeps each packet reduced to a small, fast-to-process record rather
than carrying its full raw content through the pipeline. Any record that
triggers a detection rule is written, with a timestamp and the reason it
was flagged, into a lightweight local SQLite database --- this log is
the single source of truth that the analysis layer and dashboard read
from; nothing downstream re-examines raw packets. The diagram below
traces this flow end-to-end, from a raw captured packet to a
plain-language statement on the dashboard.

![Embedded
figure](Project_Synopsis_IDS_Software_Formatted_assets/image3.png)

*Figure 2.2: End-to-end data flow, from raw packet capture to
plain-language dashboard output.*

**2.3 CORE MODULES AND WORKFLOW**

**2.3.1 Packet Capture**

A Python script using the Scapy library opens the chosen network
interface in a listening mode and captures every packet passing through
it, continuously, in the background. Each packet is handed off, one at a
time, to the next stage as it arrives --- this is a live, ongoing
process, not a batch job run periodically.

**2.3.2 Rule Engine**

Each extracted record is checked against a small set of independent
detection rules, each maintaining its own short-term memory (a sliding
time window) of recent activity so it can recognise patterns across
multiple packets:

Port Scan Rule: flags a source IP attempting connections to more than a
defined number of distinct destination ports within a short time window.

Connection-Rate (SYN Flood) Rule: flags a source IP initiating an
unusually high number of new connection attempts in a short window
without completing them.

ARP Spoofing Rule: maintains a table of IP-to-MAC associations and flags
an alert if an IP address suddenly appears to be claimed by a different
MAC address than previously observed.

Blocklist Match Rule: checks each destination IP against a locally
stored list of known-malicious IP addresses, flagging any connection
attempt toward one.

**2.3.3 Analysis Layer and Dashboard**

Running on a short interval, a separate process reads newly logged
alerts and computes higher-level, human-relevant observations --- which
device generated the most flagged activity, whether any device has not
been seen before, and whether flagged activity occurred during unusual
hours. Each observation is converted into a short, specific,
plain-English statement (for example, "A device on your network
attempted to access 40 different services in 10 seconds --- this can
indicate scanning activity") and displayed on a lightweight local web
dashboard, alongside a device list, a simple activity chart, and a
colour-coded status indicator.

**2.4 DEVELOPMENT METHODOLOGY**

The system will be developed incrementally: packet capture and field
extraction first, followed by one detection rule at a time (starting
with the simplest, blocklist matching, before progressing to the
stateful port-scan, connection-rate, and ARP-spoofing rules), followed
by alert logging, the analysis layer, and finally the dashboard. This
order ensures a working, demonstrable pipeline exists at every stage of
development rather than a collection of untested components assembled at
the end.

Once the core engine is functional, it will be evaluated by running the
same captured traffic --- either live or as a saved packet-capture file
--- through both the custom-built engine and Suricata, configured with a
standard ruleset. The two sets of alerts will be compared to identify
true positives both systems agree on, cases Suricata catches that the
custom engine misses, and false positives generated by the custom
engine, which will be used to tune detection thresholds. This comparison
is treated as part of the development methodology rather than an
afterthought, since it directly informs how the rules are refined.

**CHAPTER 3: APPLICATIONS AND SCOPE**

**3.1 APPLICATIONS**

Small offices without dedicated IT staff gain basic visibility into
their own network without needing to interpret technical logs
themselves.

Serves as a teaching and demonstration tool for explaining how intrusion
detection concepts --- port scanning, ARP spoofing, flooding,
blocklisting --- work in practice, since the logic is transparent and
modifiable rather than hidden inside a commercial product.

Provides a foundation that can later be extended with additional rules,
a larger blocklist, or a transition to a more capable engine such as
Suricata, once the underlying concepts are well understood.

The comparison exercise against Suricata produces a genuine, original
piece of analysis suitable for a project report or viva, demonstrating
where a simple detector\'s limitations lie relative to a mature,
professionally maintained tool.

**3.2 FUTURE SCOPE**

The present design is scoped deliberately narrowly, and several
extensions are identified as natural next steps rather than part of the
current build. The system currently detects and alerts only;
repositioning the capture point inline rather than on a mirrored port
would allow it to evolve from a pure IDS into an IPS capable of actively
blocking flagged traffic. The detection ruleset is limited to four
hand-written rules; this could be extended with additional
signature-based rules or, longer term, a statistical anomaly-detection
layer trained on the specific network it is deployed on. The blocklist
currently relies on a periodically refreshed public feed; a future
version could support multiple feeds or a locally curated list. Finally,
threshold-based rules are known to produce false positives under unusual
but legitimate traffic patterns; a planned refinement is an adjustable
sensitivity setting the end user can tune from the dashboard itself,
without needing to edit code.

Taken together, this project is intended to demonstrate a complete,
end-to-end intrusion detection pipeline built from first principles,
with a clear and honest account of its current limitations and a
concrete path for extending it beyond the scope of this synopsis.
