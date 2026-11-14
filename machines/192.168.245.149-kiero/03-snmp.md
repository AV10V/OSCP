# 03 — SNMP: the leak that hands over the credentials

`161/udp` was the only unambiguous UDP result from chapter 01. This chapter turns it into a
username and a password policy statement.

---

## 3.1 Why SNMP first

SNMP on a Linux host is almost always `net-snmp`/`snmpd`, and it is almost always misconfigured in
the same two ways on lab boxes: the default community string `public` is left in place, and
somebody has added a custom `extend` entry that runs a host command. The `extend` mechanism is
attractive for admins because it lets you expose arbitrary script output as an OID — and
disastrous when the *description* of that extend is itself sensitive.

## 3.2 Finding the community string

Try the short default list before anything heavier.

```bash
for c in public private manager internal; do
  echo "=== community: $c ==="
  snmpwalk -v1 -c "$c" -t 5 -r 1 192.168.245.149 1.3.6.1.2.1.1
done
```

`private`, `manager`, `internal` all returned `Timeout: No Response`. `public` replied:

```
iso.3.6.1.2.1.1.1.0 = STRING: "Linux lab-pwk2-student-cl5-149-ubuntu1804-kiero-247-195 5.9.0-050900-generic #202010112230 SMP Sun Oct 11 22:34:01 UTC 2020 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (1330028) 3:41:40.28
iso.3.6.1.2.1.1.4.0 = STRING: "Me <me@example.org>"
iso.3.6.1.2.1.1.5.0 = STRING: "lab-pwk2-student-cl5-149-ubuntu1804-kiero-247-195"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
```

**Reading it:**

- Community string is the default `public` — unauthenticated read access to the whole MIB tree.
- `sysDescr` gives the kernel build (`#202010112230` — Oct 2020) and the FQDN.
- The hostname is `lab-pwk2-student-cl5-149-ubuntu1804-kiero-247-195`. Break it apart:
  `kiero` is the box name, `ubuntu1804` the image, `cl5` the class/challenge. **"kiero" is also a
  username candidate** — this is a naming habit worth noticing, since a username is half of a
  credential.
- `sysContact: Me <me@example.org>` and `sysLocation: Sitting on the Dock of the Bay` are
  untouched package defaults, confirming snmpd was never hardened.

## 3.3 Enumerating the useful tables

Do not stop at `system`. On Linux, `1.3.6.1.2.1.25` (host resources) exposes the process table and
the installed package list, which is effectively a free `ps` and `dpkg -l` without a shell.

```bash
# processes
snmpwalk -v1 -c public 192.168.245.149 1.3.6.1.2.1.25.4.2.1.2 | sed -E 's/.*STRING: //' | sort -u

# installed software
snmpwalk -v1 -c public 192.168.245.149 1.3.6.1.2.1.25.6.3.1.2 | sed -E 's/.*STRING: //' | sort -u
```

Non-kernel processes:

```
accounts-daemon
agetty
apache2
atd
cron
dbus-daemon
ModemManager
multipathd
networkd-dispat
polkitd
qemu-ga
rsyslogd
snapd
snmpd
sshd
systemd
systemd-journal
systemd-logind
systemd-network
systemd-resolve
systemd-timesyn
systemd-udevd
udisksd
unattended-upgr
upowerd
uuidd
vsftpd
```

Packages of interest:

```
apache2_2.4.41-4ubuntu3.23_amd64
openssh-server_1:8.2p1-4ubuntu0.13_amd64
vsftpd_3.0.3-12_amd64
snmpd_5.8+dfsg-2ubuntu2.5_amd64
```

**Reading it:**

- `qemu-ga` confirms this is a VM on a hypervisor — consistent with a lab image.
- `vsftpd_3.0.3-12` — note the *package* version differs from the banner `vsftpd 3.0.5`. The banner
  reports the upstream release, the package reports the Ubuntu revision. Not a contradiction, but
  worth knowing so you do not chase a phantom version mismatch.
- **`apache2_2.4.41-4ubuntu3.23`** — the `3.23` revision is the backport containing the
  CVE-2021-41773 fix. This independently confirms the 400 responses from chapter 02 and lets me
  close that thread with evidence.
- No `docker`, no `mysql`, no `postgresql`, no unusual service — nothing else to pivot to locally.

Process command lines (`1.3.6.1.2.1.25.4.2.1.5`) and paths (`...1.4`) mostly show stock argv, but
one line matters:

```
iso.3.6.1.2.1.25.4.2.1.5.5394 = STRING: "/etc/vsftpd.conf"
```

That is `vsftpd` started with an explicit config — normal, but it confirms FTP is configured
deliberately rather than left at package defaults, which makes a non-default (i.e. weak,
admin-set) credential more likely.

## 3.4 The extend table — the actual win

The UCD/net-snmp agent supports `extend` entries, which live under
`1.3.6.1.4.1.8072.1.3.2` (`nsExtendTable`). Always walk this subtree; it is the single most
valuable OID range on a Linux SNMP target.

```bash
snmpwalk -v1 -c public 192.168.245.149 1.3.6.1.4.1.8072.1.3.2
```

```
iso.3.6.1.4.1.8072.1.3.2.1.0 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.2.1.2.5.82.69.83.69.84 = STRING: "./home/john/RESET_PASSWD"
iso.3.6.1.4.1.8072.1.3.2.2.1.3.5.82.69.83.69.84 = ""
iso.3.6.1.4.1.8072.1.3.2.2.1.4.5.82.69.83.69.84 = ""
iso.3.6.1.4.1.8072.1.3.2.2.1.5.5.82.69.83.69.84 = INTEGER: 5
iso.3.6.1.4.1.8072.1.3.2.2.1.6.5.82.69.83.69.84 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.2.1.7.5.82.69.83.69.84 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.2.1.20.5.82.69.83.69.84 = INTEGER: 4
iso.3.6.1.4.1.8072.1.3.2.2.1.21.5.82.69.83.69.84 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.3.1.1.5.82.69.83.69.84 = STRING: "Resetting password of kiero to the default value"
iso.3.6.1.4.1.8072.1.3.2.3.1.2.5.82.69.83.69.84 = STRING: "Resetting password of kiero to the default value"
iso.3.6.1.4.1.8072.1.3.2.3.1.3.5.82.69.83.69.84 = INTEGER: 1
iso.3.6.1.4.1.8072.1.3.2.3.1.4.5.82.69.83.69.84 = INTEGER: 0
iso.3.6.1.4.1.8072.1.3.2.4.1.2.5.82.69.83.69.84.1 = STRING: "Resetting password of kiero to the default value"
```

### Decoding the index

The OID suffix `5.82.69.83.69.84` is not opaque. The first component is the string length, the
rest are ASCII character codes:

| Component | Meaning |
|---|---|
| `5` | length of the extend name |
| `82` | `R` |
| `69` | `E` |
| `83` | `S` |
| `69` | `E` |
| `84` | `T` |

So the extend is named **`RESET`**. Decoding these by hand is worth doing once — it makes tables
where the *key* carries the meaning readable at a glance:

```bash
# generic decoder for an nsExtend index suffix
python3 -c "
s='82.69.83.69.84'.split('.')
print(''.join(chr(int(x)) for x in s[1:]))"
```

### What each column tells us

| Column | Value | Meaning |
|---|---|---|
| `...2.1.2` | `./home/john/RESET_PASSWD` | the command the agent executes |
| `...2.1.3` / `.4` | `""` | no stdin, no arguments |
| `...2.1.5` | `INTEGER: 5` | cache timeout type (5 = cache for a set period) |
| `...2.1.6` | `INTEGER: 1` | output type: run the command through a shell |
| `...2.1.20` / `.21` | `4`, `1` | exec error codes — clean run |
| `...3.1.1` | `"Resetting password of kiero to the default value"` | **the MIB description string** |
| `...3.1.4` | `INTEGER: 0` | exit status 0 — the command succeeded |

Three separate pieces of intelligence, all without credentials:

1. **A username: `kiero`.** Confirmed twice over — the description names it, and the hostname
   `...-kiero-...` independently suggested it.
2. **A password policy statement: "the default value".** Not a hint, a specification. This
   converts the password from "unknown, brute force everything" to "try the obvious defaults for
   this specific account".
3. **A privileged binary: `/home/john/RESET_PASSWD`.** Something on this host exists whose job is
   to reset `kiero`'s password, which means it runs as root. That is a privilege-escalation
   candidate for later — logged and set aside for chapter 06.

> **Two-for-one.** This single OID range supplied the entry point *and* foreshadowed the privesc.
> That is why `nsExtendTable` is always worth a walk.

### A note on the extend output

The executed output (`...4.1.2.<index>.1`) contains only the description text, not a password. The
cached value is what the script printed, and the script prints a status line. There is no
credential to harvest *directly* from the extend — the value is purely the hint.

Attempting to read the other output columns with `snmpget` returned `noSuchName`, which is correct
behaviour: those columns only materialise for extends that emit multiple lines or explicit exit
codes, and this one does not.

```bash
snmpget -v1 -c public 192.168.245.149 1.3.6.1.4.1.8072.1.3.2.4.1.3.5.82.69.83.69.84
# Error in packet
# Reason: (noSuchName) There is no such variable name in this MIB.
```

## 3.5 Other community strings

Worth one pass to see whether a *write* community exists — `private` would allow `snmpget`-style
`SET` requests and a completely different attack path. All failed:

```bash
for c in kiero oscp oscp.exam student cl5 lab public2 cisco; do
  printf "%-12s " "$c"
  snmpget -v1 -c "$c" -t 4 -r 0 192.168.245.149 1.3.6.1.2.1.1.5.0
done
```

```
kiero        Timeout: No Response from 192.168.245.149.
oscp         Timeout: No Response from 192.168.245.149.
oscp.exam    Timeout: No Response from 192.168.245.149.
student      Timeout: No Response from 192.168.245.149.
cl5          Timeout: No Response from 192.168.245.149.
lab          Timeout: No Response from 192.168.245.149.
public2      Timeout: No Response from 192.168.245.149.
cisco        Timeout: No Response from 192.168.245.149.
```

Read-only access via `public` only. The path forward is the credential hint, not SNMP writes.

---

## Result of this chapter

| Artefact | Value |
|---|---|
| Community string | `public` (read-only) |
| Username | **`kiero`** |
| Password policy | **default value** — a fixed, known string |
| Privesc candidate | `/home/john/RESET_PASSWD` (runs as root by design) |

→ [04 — FTP](04-ftp.md): apply the username to the one service that accepts passwords.
