#!/usr/bin/env bash
# SANDBOX TEST ONLY: proves that deploy/rakshak-fw (installed at /usr/local/sbin/rakshak-fw)
# refuses dangerous firewall commands and that a real block through it drops traffic.
# Needs the sandbox fixtures: nginx on 10.99.0.1:8081, test source addresses 10.99.0.3 and .6.
set -u
cd "$(dirname "$0")/.."
F="sudo -n /usr/local/sbin/rakshak-fw"
echo "rakshak-fw live check - $(date -u '+%Y-%m-%d %H:%M UTC') - $(sudo -n iptables --version)"
echo "--- refused commands (expected exit=2)"
for a in "4 -F" "4 -X RAKSHAK-BLOCK" "4 -I INPUT 1 -j ACCEPT" "4 -A INPUT -s 10.99.0.6/32 -j DROP" \
         "4 -A RAKSHAK-BLOCK -s 0.0.0.0/0 -j DROP" "4 -A RAKSHAK-BLOCK -s 10.0.0.0/8 -j DROP" \
         "4 -A RAKSHAK-BLOCK -s 127.0.0.1/32 -j DROP" "6 -A RAKSHAK-BLOCK -s 10.99.0.6/32 -j DROP" \
         "4 -A RAKSHAK-BLOCK -s 10.99.0.6/32 -j ACCEPT" "4 -A RAKSHAK-BLOCK -s 10.99.0.6/32 -j DROP -i lo"; do
  $F $a >/dev/null 2>&1; echo "exit=$? : rakshak-fw $a"
done
echo "--- Rakshak IptablesEnforcer through the helper (real traffic)"
PYTHONPATH=. .venv/bin/python - <<'EOF'
import subprocess
from rakshak.enforcer import IptablesEnforcer
e = IptablesEnforcer("sudo -n /usr/local/sbin/rakshak-fw 4", "sudo -n /usr/local/sbin/rakshak-fw 6")
def code(src):
    return subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--interface", src,
                           "--max-time", "3", "http://10.99.0.1:8081/"], capture_output=True, text=True).stdout
print("enforcer ready:", e.ready, e.error)
print("before block   10.99.0.6 ->", code("10.99.0.6"))
print("block          ", e.block("10.99.0.6", 60))
print("while blocked  10.99.0.6 ->", code("10.99.0.6"), "(000 = no answer)   10.99.0.3 ->", code("10.99.0.3"))
print("unblock        ", e.unblock("10.99.0.6"))
print("after unblock  10.99.0.6 ->", code("10.99.0.6"))
print("block loopback ", e.block("127.0.0.1", 60))
EOF
echo "--- chain after test"
sudo -n iptables -S RAKSHAK-BLOCK
