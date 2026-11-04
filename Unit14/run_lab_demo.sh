#!/bin/bash
# run_lab_demo.sh -- starts every lab component, runs all demo scenarios, then stops everything.
# LAB USE ONLY. All traffic stays on 127.0.0.1.
set -e
cd "$(dirname "$0")"

echo "Starting plaintext bank (6000) and HTTP MITM proxy (6001)..."
python3 bank_http_server.py >/tmp/bank_http.log 2>&1 &
PID1=$!
python3 mitm_http_proxy.py >/tmp/mitm_http.log 2>&1 &
PID2=$!
sleep 1.5

echo
echo "### PART 1: Plaintext HTTP -- MITM reads credentials directly ###"
echo "--- victim believes they are talking to the bank, but the attacker's proxy is in the path ---"
curl -s -d "username=alice&password=alice123" http://127.0.0.1:6001/login | grep -o "Logged in!\|Invalid login"
sleep 0.5
echo "--- attacker's proxy console ---"
cat /tmp/mitm_http.log

kill $PID1 $PID2 2>/dev/null
sleep 1

echo
echo "Starting HTTPS bank (6443) and TLS MITM proxy (6444)..."
python3 bank_https_server.py >/tmp/bank_https.log 2>&1 &
PID3=$!
python3 tls_mitm_proxy.py >/tmp/tls_mitm.log 2>&1 &
PID4=$!
sleep 1.5

echo
echo "### PART 2: HTTPS with PROPER certificate validation -- MITM is blocked ###"
python3 secure_client.py 6444 || true

echo
echo "### PART 3: HTTPS with certificate validation DISABLED -- MITM succeeds ###"
python3 insecure_client.py 6444

sleep 0.5
echo
echo "--- attacker's TLS proxy console ---"
cat /tmp/tls_mitm.log

kill $PID3 $PID4 2>/dev/null
echo
echo "Demo complete."
