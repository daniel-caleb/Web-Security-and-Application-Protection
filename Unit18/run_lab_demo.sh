#!/bin/bash
# run_lab_demo.sh -- starts the authorization server and resource server, runs the
# full OAuth 2.0 PKCE flow, then runs the JWT inspection and pitfalls demos.
# LAB USE ONLY. All traffic stays on 127.0.0.1.
set -e
cd "$(dirname "$0")"

echo "Starting authorization server (7000) and resource server (7002)..."
python3 auth_server.py >/tmp/auth_server.log 2>&1 &
PID1=$!
python3 resource_server.py >/tmp/resource_server.log 2>&1 &
PID2=$!
sleep 1.5

echo
echo "################################################################"
echo "# PART 1: OAuth 2.0 Authorization Code flow with PKCE"
echo "################################################################"
python3 run_oauth_demo.py

kill $PID1 $PID2 2>/dev/null
sleep 1

echo
echo "################################################################"
echo "# PART 2: Decoding a JWT by hand (no library, no secret needed)"
echo "################################################################"
python3 jwt_inspect.py

echo
echo "################################################################"
echo "# PART 3: Five common JWT verification pitfalls"
echo "################################################################"
python3 jwt_pitfalls.py

echo
echo "Demo complete."
