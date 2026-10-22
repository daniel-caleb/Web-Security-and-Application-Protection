# Lab 1: Wireshark Packet Capture and Analysis

**Module:** 5 – Web Security and Application Protection
**Unit:** 1 – LAN Security
**Estimated Duration:** 60–75 minutes
**Difficulty:** Beginner

## Objective
Capture live network traffic on a LAN and analyze it to identify protocols, hosts, and plaintext data exposure.

## Prerequisites
- Basic understanding of the OSI/TCP-IP model
- A VM or lab machine with network access

## Tools Required
- Wireshark (latest stable version)
- A second device or virtual machine on the same network to generate traffic

## Ethics & Safety Note
Only capture traffic on networks and devices you own or have explicit written permission to test. Capturing traffic on networks you do not control is illegal in most jurisdictions.

## Step-by-Step Instructions

### Step 1: Install and Launch Wireshark
1. Download Wireshark from the official site (wireshark.org) or install via package manager:
   ```
   sudo apt install wireshark
   ```
2. Launch Wireshark with administrative/root privileges.

### Step 2: Identify the Correct Interface
1. On the Wireshark start screen, review the list of available interfaces (e.g., `eth0`, `wlan0`).
2. Select the interface connected to your lab network.

### Step 3: Start a Capture
1. Double-click the chosen interface to begin capturing.
2. Open a browser on the same machine or network and visit an HTTP (non-HTTPS) test site, e.g., `http://testphp.vulnweb.com`.
3. Let the capture run for 1–2 minutes while generating traffic (browsing, pinging another host, etc.).

### Step 4: Apply Display Filters
Use the filter bar to narrow results:
```
http
dns
arp
tcp.port == 80
ip.addr == <target_IP>
```
Observe how each filter isolates specific traffic types.

### Step 5: Analyze an HTTP Request
1. Filter by `http.request`.
2. Click on a GET request packet.
3. Expand the "Hypertext Transfer Protocol" layer in the packet details pane.
4. Right-click the packet and choose **Follow > HTTP Stream** to view the full plaintext request/response.
5. Note any credentials, cookies, or sensitive data visible in plaintext.

### Step 6: Analyze DNS Traffic
1. Filter by `dns`.
2. Identify DNS query and response packets.
3. Note the queried domain name and resolved IP address.

### Step 7: Save and Document the Capture
1. Go to **File > Save As** and save the capture as `lab1_capture.pcapng`.
2. Record in your lab notebook:
   - Number of HTTP packets captured
   - Any plaintext credentials or sensitive data found
   - The resolved IP for at least one DNS query

## Expected Outcome
Learners can capture, filter, and interpret packet-level data, and can explain why unencrypted protocols like HTTP expose sensitive data on the wire.

## Cleanup
- Stop the capture (red square icon).
- Close Wireshark without capturing further traffic beyond the lab exercise.

## Review Questions
1. Why does HTTP traffic expose data that HTTPS would protect?
2. What is the purpose of a display filter versus a capture filter?
3. How could an attacker misuse the "Follow TCP Stream" feature on an unsecured network?
