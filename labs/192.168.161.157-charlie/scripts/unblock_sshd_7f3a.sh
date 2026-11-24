#!/usr/bin/env bash
# unblock_sshd_7f3a.sh
#
# Run as root ON the target (e.g. /home/cassie/rootbash -p -c 'bash unblock_sshd_7f3a.sh').
#
# Removes the `DenyUsers cassie` line that makes every SSH attempt fail before
# authentication, backs the file up first, and refuses to restart sshd unless
# `sshd -t` accepts the new config.
set -u

USER_NAME="${1:-cassie}"
CONF=/etc/ssh/sshd_config
BAK="/home/${USER_NAME}/sshd_config.bak"

if [ "$(id -u)" -ne 0 ]; then
  echo "[-] must run as root" >&2
  exit 1
fi

if ! grep -qiE "^[[:space:]]*DenyUsers[[:space:]].*\b${USER_NAME}\b" "$CONF"; then
  echo "[*] no DenyUsers entry for ${USER_NAME} - nothing to remove"
else
  cp -a "$CONF" "$BAK" || exit 1
  echo "[+] backup: $BAK"

  # delete only the DenyUsers line(s) that name this account
  tmp=$(mktemp)
  grep -viE "^[[:space:]]*DenyUsers[[:space:]].*\b${USER_NAME}\b" "$CONF" > "$tmp"
  cat "$tmp" > "$CONF"          # in place: keeps owner, mode and inode
  rm -f "$tmp"
  echo "[+] removed DenyUsers ${USER_NAME} from $CONF"
fi

if /usr/sbin/sshd -t; then
  echo "[+] sshd -t: config OK"
else
  echo "[-] sshd -t rejected the config - restoring the backup" >&2
  [ -f "$BAK" ] && cat "$BAK" > "$CONF"
  exit 1
fi

systemctl restart ssh 2>/dev/null || service ssh restart
echo "[+] ssh restarted"
echo
grep -vE '^[[:space:]]*#' "$CONF" | grep -vE '^[[:space:]]*$' | grep -iE 'denyusers|allowusers|permitrootlogin|pubkeyauth|passwordauth'
