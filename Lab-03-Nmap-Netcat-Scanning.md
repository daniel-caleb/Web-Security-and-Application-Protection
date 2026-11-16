# Lab 3: Network Scanning with Nmap and Netcat

**Module:** 5 – Web Security and Application Protection
**Unit:** 1 – LAN Security
**Estimated Duration:** 90 minutes
**Difficulty:** Beginner–Intermediate

## Objective
Use Nmap and Netcat to perform host discovery, port scanning, service enumeration, and basic banner grabbing.

## Prerequisites
- Basic command-line familiarity
- Lab 1 and 2 completed

## Tools Required
- Kali Linux (or any Linux distro) with Nmap and Netcat installed
- A target VM (e.g., Metasploitable2) on the isolated lab network

## Ethics & Safety Note
Only scan systems you own or are authorized to test. Scanning third-party systems without permission is illegal under laws such as the Computer Misuse Act / Computer Fraud and Abuse Act.

## Step-by-Step Instructions

### Step 1: Confirm Lab Network Connectivity
```
ping -c 3 <target_IP>
```

### Step 2: Host Discovery (Network Mapping)
Scan the entire subnet to discover live hosts:
```
nmap -sn 192.168.56.0/24
```
Record the list of live IP addresses returned.

### Step 3: Basic Port Scan
```
nmap <target_IP>
```
Record the open ports and the services Nmap associates with them.

### Step 4: Service and Version Detection
```
nmap -sV <target_IP>
```
Note the exact service versions returned (e.g., Apache 2.2.8).

### Step 5: OS Detection
```
sudo nmap -O <target_IP>
```
Record the guessed operating system and confidence percentage.

### Step 6: Full Port Range Scan
```
nmap -p- <target_IP>
```
Compare results against Step 3 — note any additional high-numbered ports discovered.

### Step 7: Vulnerability Scanning with Nmap Scripts (NSE)
```
nmap --script vuln <target_IP>
```
Record any vulnerabilities flagged (e.g., outdated FTP/SMB versions).

### Step 8: Banner Grabbing with Netcat
Connect to a discovered open port manually:
```
nc -nv <target_IP> 21
```
Observe the banner returned by the FTP service (or another open port). Record the exact banner text.

### Step 9: Simple Netcat Listener/Chat (Networking Fundamentals)
On one VM:
```
nc -lvp 4444
```
On a second VM:
```
nc <first_VM_IP> 4444
```
Type a message on one side and confirm it appears on the other — demonstrating raw TCP communication.

### Step 10: Document Findings
Summarize in a short report:
- Live hosts discovered
- Open ports and services per host
- Any vulnerabilities flagged by `--script vuln`
- Recommended remediation (e.g., disable unused services, patch outdated versions)

## Expected Outcome
Learners can perform host discovery, port/service scanning, OS fingerprinting, and basic banner grabbing, and can translate findings into remediation recommendations.

## Cleanup
- Close all Netcat listener sessions.
- Save scan outputs for the module portfolio (`nmap -oN results.txt <target_IP>`).

## Review Questions
1. What is the difference between a SYN scan (`-sS`) and a full connect scan (`-sT`)?
2. Why is banner grabbing considered a reconnaissance risk for organizations?
3. Name two legitimate defensive uses of Nmap for a network administrator.
