# Methodology

The loop I run on every box, in order, with the rule that makes each step worth its time. This is
deliberately shallow-then-deep: cheap checks across the whole surface first, expensive work only
where evidence points.

---

## Phase 0 — Setup

```bash
mkdir -p /tmp/<box> && cd /tmp/<box>
export TARGET=<ip>
```

Everything for the box lands in one directory: scan output, loot, evidence. It makes writing the
report afterwards trivial and stops me confusing two boxes' output.

---

## Phase 1 — Reachability and TCP

| Step | Command | Rule |
|---|---|---|
| Ping | `ping -c 2 -W 2 $TARGET` | TTL tells you the OS before you scan (64 Linux, 128 Windows) |
| Full TCP | `nmap -p- --min-rate 3000 -T4 -oN full_tcp.txt $TARGET` | **Always `-p-`.** A top-1000 scan is a guess |
| Versions | `nmap -sV -sC -p<open> -oN services.txt $TARGET` | Only the open ports; `-sC` is cheap and occasionally decisive |

**Decision:** for each open port, ask "what is the *configuration* weakness most likely to be, given
this version?" Version CVEs come last — most boxes are misconfigured, not unpatched.

---

## Phase 2 — UDP (do not skip this)

```bash
nmap -sU --top-ports 30 -T4 --max-retries 1 --host-timeout 180s $TARGET
```

If `161/udp` is open:

```bash
for c in public private manager internal; do
  snmpwalk -v1 -c "$c" -t 5 -r 1 $TARGET 1.3.6.1.2.1.1 2>&1 | head -3
done
```

Then, on success, always:

```bash
snmpwalk -v1 -c public $TARGET 1.3.6.1.4.1.8072.1.3.2   # nsExtendTable — the money tree
snmpwalk -v1 -c public $TARGET 1.3.6.1.2.1.25.4.2.1.2   # process names
snmpwalk -v1 -c public $TARGET 1.3.6.1.2.1.25.6.3.1.2   # installed packages
snmpwalk -v1 -c public $TARGET 1.3.6.1.2.1.4.20.1.1     # interface IPs
```

`nsExtendTable` gives you the commands the agent runs plus the admin's own description of them.
Descriptions are written for an internal audience and routinely name accounts and policies.

---

## Phase 3 — Per-service enumeration

For each service, in the order that historically pays fastest.

### HTTP/HTTPS

```bash
curl -s -i http://$TARGET/ | head -20          # stock page? framework? redirect?
for p in robots.txt sitemap.xml .git/ .htaccess server-status; do
  curl -s -o /dev/null -w "%{http_code} %{size_download}  /$p\n" http://$TARGET/$p
done
feroxbuster -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 40 -d 2 --smart --no-state -q
```

- Note the **404 body size** — it is your filter for everything after.
- Vhosts: `ffuf -u http://$TARGET/ -H "Host: FUZZ" -w <subdomains> -fr "<default page text>"`.
- Timebox it. If the page is byte-identical to a stock install and two wordlists agree, stop.

### FTP

```bash
ftp -n -v $TARGET <<< $'user anonymous anon@test\nls\nbye'   # 530 on USER = anonymous_enable=NO
hydra -L users.txt -P pass.txt -t 4 -f ftp://$TARGET
```

Try the account name as the password. Check for key material, configs, and backups in the data
directory — a shared `/srv/ftp` often leaks a *different* account's secrets.

### SSH

```bash
ssh -i key -o BatchMode=yes user@$TARGET id      # never point a key at a host without -o BatchMode
ssh-keygen -l -f key                             # read the comment first: it names the user
```

### SMB

```bash
nxc smb $TARGET -u '' -p '' --shares
nxc smb $TARGET -u guest -p '' --shares
nxc smb $TARGET -u user -p pass -d DOMAIN --shares
```

---

## Phase 4 — Foothold

Get a shell, then **immediately** stabilise and record identity:

```bash
id; hostname; sudo -n -l; uname -a
```

Do not start hunting for privesc before you know exactly which uid and groups you hold — the
escalation path depends on it.

---

## Phase 5 — Local enumeration (Linux)

Send one script over one connection and read one report:

```bash
ssh user@$TARGET 'bash -s' < enum.sh
```

Checklist, in the order that finds things:

| # | Check | Command |
|---|---|---|
| 1 | sudo rights | `sudo -n -l` |
| 2 | SUID, excluding snap noise | `find / -perm -4000 -type f 2>/dev/null \| grep -v '^/snap'` |
| 3 | Capabilities | `getcap -r / 2>/dev/null` |
| 4 | Cron | `cat /etc/crontab; ls -la /etc/cron.*` |
| 5 | Writable service files | `find / -writable -type f -path '*/etc/*' 2>/dev/null` |
| 6 | Listening sockets | `ss -tlnp` |
| 7 | Home directories | `ls -la /home/*` — this box had the SUID helper in a user's home |
| 8 | History and keys | `ls -la ~/.ssh; cat ~/.bash_history` |
| 9 | Kernel | `uname -a` — only if 1–8 are empty |
| 10 | Password reuse | the foothold password against `sudo -S` and other users |

**Rule:** a *custom* SUID binary beats every generic exploit. Read it before reaching for
`linpeas` output tables.

---

## Phase 6 — Binary analysis (when a SUID binary looks custom)

```bash
file /path/binary                    # not stripped? then function names survive
strings -a /path/binary | head -40   # look for system, popen, exec*, and bare command names
objdump -d -M intel /path/binary | sed -n '/<main>:/,/^$/p'
readelf -d /path/binary | grep -E 'BIND_NOW|FLAGS'   # is RELRO full? (memory bugs are then out)
```

What you are looking for, in priority order:

1. `system()` / `popen()` with a **bare command name** → `PATH` hijack (CWE-426)
2. `setuid(0)`/`seteuid(0)` **before** that call → the shell will not drop privileges → full root
3. A writable path used by root → symlink or overwrite attack
4. A shell escape in a pager/editor it invokes

If the binary is setuid **and** setgid, or lives in a user-writable directory, the box author is
telling you this is the path.

---

## Phase 7 — Post-exploitation and reporting

```bash
cat /root/proof.txt; cat /home/*/local.txt
ip a; ip r          # can this host pivot? (single NIC + default route = no)
```

Record: exact flags, the `id` output as root, the mechanism in one paragraph, and every command
with its output. Then clean up.

### Cleanup checklist

- Remove every file you created, then **verify** with `ls`.
- Revert any file you modified.
- Do not change credentials you do not own; if an exploit would have (this box's `chpasswd`),
  note that it did not run.
- Note in the report what you changed and what you left alone.

---

## Timeboxing heuristics

| Situation | Budget | Move on when |
|---|---|---|
| Web on a stock default page | 10 min | Two wordlists + vhosts agree there is nothing |
| Version-CVE rabbit hole | 5 min | The package revision shows the backport |
| Credential guessing | 5 min per service | Account-specific defaults exhausted |
| Generic privesc sweep | 15 min | A custom SUID/service/cron finding exists |

The recurring lesson: **spend the time on the surface you have not looked at, not on the one you
have already disproved.** On this box, thirty UDP ports were worth more than an hour of web.
