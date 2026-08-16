#!/usr/bin/env bash
# security_audit_scan.sh
# Read-only security audit — makes NO changes to the system.
# Run on each machine (Agent, Manager, Forensics) and save output.
#
# Usage: bash security_audit_scan.sh > audit_scan_$(hostname)_$(date +%Y%m%d).txt 2>&1

echo "=================================================================="
echo "SECURITY AUDIT SCAN — $(hostname) — $(date -u +'%Y-%m-%d %H:%M UTC')"
echo "=================================================================="

echo -e "\n--- [1] CREDENTIAL HYGIENE ---"

echo ">> Hardcoded passwords/secrets in project files (excludes .git, venv, node_modules):"
find ~ -maxdepth 4 \( -path "*/edr-venv/*" -o -path "*/.git/*" -o -path "*/node_modules/*" \) -prune -o \
  -type f \( -name "*.py" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.sh" -o -name "*.env" \) -print 2>/dev/null | \
  xargs grep -liE "(password|secret|api_key|apikey)\s*[:=]\s*['\"][^'\"]{4,}" 2>/dev/null | head -20

echo -e "\n>> File permissions on sensitive files (.env, .pem, credentials):"
find ~ -maxdepth 3 \( -name "*.env" -o -name "*.pem" -o -name "*credential*" -o -name "*.key" \) -exec ls -la {} \; 2>/dev/null

echo -e "\n>> World-readable sensitive files (permission mode ends in non-0):"
find ~ -maxdepth 4 \( -name "*.env" -o -name "*.pem" -o -name "*_key*" \) -perm -o+r 2>/dev/null

echo -e "\n--- [2] NETWORK EXPOSURE ---"

echo ">> Listening ports and bind addresses (0.0.0.0 = internet-reachable if SG allows):"
ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null

echo -e "\n>> Current public IP (for cross-checking security group rules):"
curl -s --max-time 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null
echo ""

echo -e "\n--- [3] TLS / ENCRYPTION ---"

echo ">> Code using verify=False or curl -k (disabled TLS verification):"
grep -rn "verify=False\|verify = False" ~/healthcare-edr --include="*.py" 2>/dev/null | grep -v ".bak"
grep -rln "curl.*-k \|curl.*--insecure" ~/*.sh ~/healthcare-edr/*.sh 2>/dev/null

echo -e "\n>> Self-signed cert check on local services (if applicable):"
for port in 9200 5601 9000 9001; do
  if ss -tln 2>/dev/null | grep -q ":$port "; then
    echo "Port $port is listening — checking cert..."
    echo | timeout 3 openssl s_client -connect localhost:$port 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null
  fi
done

echo -e "\n--- [4] ACCESS CONTROL ---"

echo ">> SSH authorized_keys count + permissions:"
ls -la ~/.ssh/authorized_keys 2>/dev/null
wc -l ~/.ssh/authorized_keys 2>/dev/null

echo -e "\n>> SSH config — password auth / root login status:"
grep -E "^PasswordAuthentication|^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null

echo -e "\n>> Sudo access for current user:"
sudo -n -l 2>&1 | head -5

echo -e "\n--- [5] OS PATCH STATUS ---"

echo ">> Kernel version:"
uname -a

echo -e "\n>> Pending security updates:"
apt list --upgradable 2>/dev/null | grep -i security | wc -l
echo "(total upgradable packages, all types):"
apt list --upgradable 2>/dev/null | wc -l

echo -e "\n--- [6] DOCKER SECURITY ---"

if command -v docker &> /dev/null; then
  echo ">> Running containers + port bindings:"
  docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}" 2>/dev/null

  echo -e "\n>> Containers running as root (UID 0):"
  for c in $(docker ps --format "{{.Names}}" 2>/dev/null); do
    uid=$(docker exec "$c" id -u 2>/dev/null)
    echo "$c -> UID $uid"
  done
else
  echo "Docker not installed on this machine."
fi

echo -e "\n--- [7] LOG / EVIDENCE INTEGRITY ---"

echo ">> World-writable files in project directory (tamper risk):"
find ~/healthcare-edr -maxdepth 3 -perm -o+w -type f 2>/dev/null | grep -v ".git"

echo -e "\n>> Log files permissions:"
ls -la ~/healthcare-edr/logs/*.jsonl 2>/dev/null
ls -la ~/healthcare-edr/*.jsonl 2>/dev/null

echo -e "\n=================================================================="
echo "SCAN COMPLETE"
echo "=================================================================="
