# Unit 14 MITM Lab: Changes and Corrections

Only the fixes needed to get the lab running. Run everything from inside the `Unit14/` folder.

---

## 1. Create the `certs/` folder (required)

The scripts load certificates from `certs/...`, but in `Unit14.rar` the `.pem` files are loose next to the scripts. Without this fix, Parts 2 and 3 fail with `No such file or directory: certs/bank_cert.pem`.

```bash
cd ~/Unit14
mkdir certs
mv *.pem certs/
ls certs/        # expect: attacker_cert.pem attacker_key.pem bank_cert.pem bank_key.pem
```

---

## 2. Use a virtual environment for Flask (Kali / Debian / Ubuntu)

System Python blocks global `pip install` (`externally-managed-environment`).

```bash
python3 -m venv venv
source venv/bin/activate     # run again in every new terminal
pip install flask
```

---

## 3. Firefox error: "This address is restricted"

**Cause:** Firefox blocks port **6000** (the traditional X11 port). Ports 6001, 6443 and 6444 are not blocked.

Pick **one** fix:

### Option A: use curl (simplest)
```bash
curl -d "username=alice&password=alice123" http://127.0.0.1:6001/login
```

### Option B: browse through the attacker's proxy port
Open `http://127.0.0.1:6001/` instead of `:6000`. Log in as `alice` / `alice123` and watch the MITM terminal capture the credentials. This is also the more realistic "victim goes through the MITM" path.

### Option C: change the ports to 8000 / 8001
```bash
sed -i 's/6000/8000/g; s/6001/8001/g' bank_http_server.py mitm_http_proxy.py run_lab_demo.sh
grep -n -E "8000|8001" bank_http_server.py mitm_http_proxy.py run_lab_demo.sh
```
The plaintext bank is then at `http://127.0.0.1:8000` and the MITM at `http://127.0.0.1:8001`. The notes still say 6000/6001, so mention the change to your instructor.

> Avoid `network.security.ports.banned.override` in `about:config`. It works, but it weakens a browser protection.

---

## 4. Other fixes

| Problem | Fix |
|---|---|
| `Address already in use` | `pkill -f bank_ ; pkill -f mitm` |
| `ModuleNotFoundError: No module named 'flask'` | Venv not active: `source venv/bin/activate` |
| Ports not free before a run | `ss -ltn \| grep -E '6000\|6001\|6443\|6444'` should print nothing |
| `.sh` won't run on Windows | Use WSL2 (Ubuntu), not PowerShell |
| Part 1 MITM log is empty on a slow VM | Change `sleep 1.5` to `sleep 3` in `run_lab_demo.sh` |
| Browser certificate warning on `https://127.0.0.1:6443` / `:6444` | Expected: the certs are self-signed. On 6444 the warning is the browser rejecting the attacker's cert, and clicking through it is the Part 3 mistake |

---

## 5. Run it

```bash
bash run_lab_demo.sh
```

Expected: Part 1 captures credentials in plaintext, Part 2 is refused by the secure client, Part 3 is intercepted by the MITM (validation disabled), then `Demo complete.`
