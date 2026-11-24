# 192.168.161.156 — `vesta` (Ubuntu 18.04, VestaCP 0.9.8-27)

| | |
|---|---|
| **Hostname** | `lab-pwk2-student-cl6-156-ubuntu20-frankfurt-240-111` |
| **OS** | Ubuntu 18.04 LTS (bionic), per package suffixes and BIND/OpenSSH builds |
| **Open ports** | `21` vsftpd 3.0.3 · `22` OpenSSH 7.6p1 · `25/465/587/2525` Exim 4.90_1 · `53` BIND 9.11.3 · `80/8083` nginx · `110/143/993/995` Dovecot · `3306` MySQL 5.7.40 · `8080/8443` Apache 2.4.29 + mod_fcgid |
| **UDP** | `161` snmpd, community `public` · `53` BIND |
| **Panel** | Vesta Control Panel 0.9.8-27 (React frontend, `/static/js/main.*.chunk.js`) |
| **Difficulty** | Easy once you scan UDP — no exploit code required beyond the panel's own API |
| **Result** | root, `local.txt` and `proof.txt` |
| **Flags** | `9cfca959e54738e70905a4024d16a44a` (user) · `d4640a77ca31e0ab126751f98e819888` (root) |

---

## TL;DR — the chain

```text
UDP/161 snmpd, community "public"
  └─ nsExtendConfigTable  (NOT the OutputFull table)
     extend "reset-password"  →  /bin/sh -c "echo \"jack:3PUKsX98BMupBiCf\" | chpasswd"
        │  the password is an argument, and arguments live in the MIB
        ▼
Vesta panel  https://192.168.161.156:8083
  jack : 3PUKsX98BMupBiCf          (regular user — not admin)
  └─ /api/v1/login/session.php → token → /api/v1/login/index.php → PHPSESSID
        ▼
/api/v1/add/web + /api/v1/upload/?dir=/home/jack/web/<d>.poc/public_html
  └─ webshell executes as jack via Apache mod_fcgid  (foothold, not root)
        ▼
/api/v1/edit/mail   field v_fwd
  ';bash<…/cmdtoexec>…/cmdresult;A='
     └─ v-edit-mail-account runs under /usr/bin/sudo  →  root
        ▼
/root/proof.txt
```

## Two mistakes that compound

1. **The host publishes its own credential.** SNMP `public` is unauthenticated read access, and a
   `net-snmp` `extend` entry stores its **command line** in the MIB — including the password passed
   as an argument. The `nsExtendOutputFull` table then confirms the command had actually run:
   `"Changing password for jack."`

2. **A normal user's input reaches a root shell.** Every panel action is a thin wrapper over
   `/usr/bin/sudo /usr/local/vesta/bin/v-*`. The mail forwarding field `v_fwd` is free text, and it
   is interpolated into the command line of `v-edit-mail-account`. One `'` breaks out. The panel's
   authorisation model then means nothing: user-level access and root differ by one HTTP request.

## Why this box is worth reading

The panel is **0.9.8-27**, so every well-known panel CVE is dead:

| CVE | Affects | Here |
|---|---|---|
| CVE-2019-9859 | ≤ 0.9.8-23 | dead |
| CVE-2020-10786 / 10787 | ≤ 0.9.8-26 | dead |
| CVE-2020-10807 / 10808 | ≤ 0.9.8-26 | dead |
| CVE-2020-10966 | ≤ 0.9.8-25 | dead |
| CVE-2021-28379 | ≤ 0.9.8-27 | live, but needs an authenticated session |
| API-key LPE (#2045) | any build with `v-generate-api-key` | live, post-foothold |

There is nothing to `searchsploit`. The escalation is the panel's **design**: it exists to run
privileged commands on behalf of unprivileged users.

## Chapters

| # | File | What it covers |
|---|---|---|
| 01 | [01-reconnaissance.md](01-reconnaissance.md) | 16 TCP ports, the TLS cert that names the product, and the UDP scan that mattered |
| 02 | [02-web-enumeration.md](02-web-enumeration.md) | nginx vs Apache, the React panel, the 2586-byte false positive, version→CVE mapping |
| 03 | [03-snmp.md](03-snmp.md) | `nsExtendConfigTable`, decoding the numeric OIDs, the cleartext credential |
| 04 | [04-panel-access.md](04-panel-access.md) | token → session flow, `inc/main.php` gating, the `/usr/bin/sudo` design |
| 05 | [05-foothold.md](05-foothold.md) | web domain + upload API → webshell as the vhost user |
| 06 | [06-privilege-escalation.md](06-privilege-escalation.md) | `v_fwd` injection, payload anatomy, second-order injection, root |
| 07 | [07-flags-and-cleanup.md](07-flags-and-cleanup.md) | flags, the debris the exploit leaves, cleanup, remediation, lessons |

## Artifacts

| Path | What |
|---|---|
| [`scripts/vesta-rce-exploit.py`](scripts/vesta-rce-exploit.py) | the full exploit — domain creation, webshell upload, mailbox injection, command loop |
| [`evidence/evidence_snmp.txt`](evidence/evidence_snmp.txt) | `nsExtendConfigTable` walk, verbatim |
| [`evidence/evidence_foothold.txt`](evidence/evidence_foothold.txt) | panel fingerprint, the 2586-byte false positive, upload path |
| [`evidence/evidence_privesc.txt`](evidence/evidence_privesc.txt) | exploit run, `id`, `pwd`, both flags |

## Usage

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install requests
python3 scripts/vesta-rce-exploit.py https://192.168.161.156:8083 jack '3PUKsX98BMupBiCf'
```

The script needs a **valid panel account**, not admin. It creates a random `<10 chars>.poc` web
domain, uploads `ownwebshell.php` into its `public_html`, creates a matching mail domain and
mailbox, then injects through `v_fwd`. Each command costs three HTTP requests — it is a request
loop, not a socket.

> **Cleanup matters.** The script leaves a web domain, a mail domain, a mailbox, a webshell and a
> **persisted forwarding entry that re-executes on every mailbox save**. See chapter 07.

## Attribution

`scripts/vesta-rce-exploit.py` is from [CSpanias/vesta-rce-exploit](https://github.com/CSpanias/vesta-rce-exploit),
derived from [rekter0/exploits — vestaROOT.py](https://github.com/rekter0/exploits/blob/master/VestaCP/vestaROOT.py).
Original headers preserved. Advisory: [SSD Disclosure — VestaCP multiple vulnerabilities](https://ssd-disclosure.com/ssd-advisory-vestacp-multiple-vulnerabilities/).

Written against a machine in an authorised training range.
