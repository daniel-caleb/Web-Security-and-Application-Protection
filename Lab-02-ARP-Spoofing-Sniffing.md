# Lab 2: ARP Spoofing and Network Sniffing Detection

**Module:** 5 – Web Security and Application Protection
**Unit:** 1 – LAN Security
**Estimated Duration:** 60–75 minutes
**Difficulty:** Intermediate

## Objective
Demonstrate how ARP spoofing enables a Man-in-the-Middle position on a LAN, then detect and mitigate the attack.

## Prerequisites
- Completion of Lab 1 (Wireshark basics)
- Understanding of ARP and how MAC/IP address resolution works

## Tools Required
- An isolated virtual lab network (e.g., VirtualBox/VMware internal network) with at least 3 VMs:
  - Attacker machine (Kali Linux)
  - Victim machine
  - Gateway/router (can be simulated)
- `arpspoof` or `ettercap` (Kali default tools)
- Wireshark

## Ethics & Safety Note
This lab MUST be performed only inside an isolated virtual lab network with no connection to production or public networks. Never run ARP spoofing tools on a shared or corporate network.

## Step-by-Step Instructions

### Step 1: Set Up the Isolated Lab Network
1. Configure your hypervisor's virtual network as "Internal Network" or "Host-Only" so it cannot reach outside networks.
2. Confirm the Attacker and Victim VMs can ping each other.

### Step 2: Record Baseline ARP Table
On the Victim machine, run:
```
arp -a
```
Note the legitimate MAC address mapped to the gateway IP.

### Step 3: Launch the ARP Spoofing Attack (Attacker Machine)
1. Enable IP forwarding on the attacker:
   ```
   sudo sysctl -w net.ipv4.ip_forward=1
   ```
2. Run arpspoof to poison the victim's ARP cache:
   ```
   sudo arpspoof -i eth0 -t <victim_IP> <gateway_IP>
   sudo arpspoof -i eth0 -t <gateway_IP> <victim_IP>
   ```
   (Run in two terminals, or use `ettercap -T -M arp:remote /victim_IP// /gateway_IP//`)

### Step 4: Verify the Attack Succeeded
On the Victim machine, re-run:
```
arp -a
```
Confirm the gateway's MAC address now matches the attacker's MAC — traffic is being routed through the attacker.

### Step 5: Capture Victim Traffic
On the Attacker machine, open Wireshark and capture on the relevant interface. Filter by `ip.addr == <victim_IP>` and observe the victim's traffic passing through.

### Step 6: Detect the Attack (Defender Role)
1. On the Victim machine, install `arpwatch` or `arp-scan`:
   ```
   sudo apt install arpwatch
   ```
2. Monitor logs for duplicate/changed MAC-to-IP mappings, which indicate ARP spoofing.
3. Alternatively, use Wireshark's filter `arp.duplicate-address-detected` on the victim's capture.

### Step 7: Mitigate
Discuss and document at least two mitigations:
- Static ARP entries for critical hosts (`arp -s <IP> <MAC>`)
- Enabling Dynamic ARP Inspection (DAI) on managed switches
- Using VPNs or encrypted protocols so intercepted traffic is unreadable

### Step 8: Stop the Attack
On the attacker machine, press `Ctrl+C` to stop arpspoof and disable IP forwarding:
```
sudo sysctl -w net.ipv4.ip_forward=0
```

## Expected Outcome
Learners can execute, observe, detect, and explain mitigations for ARP spoofing attacks within a controlled environment.

## Cleanup
- Revert all VM network settings to isolated/host-only if not already.
- Clear ARP caches on all VMs (`sudo ip -s -s neigh flush all`).

## Review Questions
1. Why is ARP inherently vulnerable to spoofing?
2. What role does IP forwarding play in making the attacker transparent (MITM)?
3. How would a switch with Dynamic ARP Inspection prevent this attack?
