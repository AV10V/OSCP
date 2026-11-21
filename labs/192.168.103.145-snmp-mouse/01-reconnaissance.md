# 01 — Reconnaissance

Goal: decide whether the host is alive, what it exposes, and — because the first scan was entirely
negative — whether that negativity was real.

---

## 1.1 The scan that said nothing

```bash
mkdir -p ~/Desktop/192.168.103.145 && cd ~/Desktop/192.168.103.145
sudo nmap -Pn -sV -O --script=vuln* \
  -p 21,80,135,139,161,445,1978,3389,5986,7680 \
  192.168.103.145 -oN 192.168.103.145_nmap_vulns.txt
```

```
Nmap scan report for 192.168.103.145
Host is up.

PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
80/tcp   filtered http
135/tcp  filtered msrpc
139/tcp  filtered netbios-ssn
161/tcp  filtered snmp
445/tcp  filtered microsoft-ds
1978/tcp filtered unisql
3389/tcp filtered ms-wbt-server
5986/tcp filtered wsmans
7680/tcp filtered pando-pub
Too many fingerprints match this host to give specific OS details

Nmap done at Fri Nov 20 18:37:45 2026 -- 1 IP address, scanned in 17.14 seconds
```

**Reading it:** `Host is up` with every port `filtered` is not "no services". `filtered` means the
SYN produced no answer — `no-response` — so nmap cannot tell an open port from a closed one. On a
Windows box that is the signature of `netsh advfirewall` dropping unsolicited inbound, plus a lab
router. The scan was 17 seconds long because nothing replied to anything; that speed is itself the
tell that we were being dropped rather than refused.

Two things to note before moving on:

- **`-Pn` was correct.** Without it nmap would have declared the host down and skipped scanning.
- **`-sV` had nothing to fingerprint.** "Too many fingerprints match" is nmap admitting it never got
  a banner, not a real ambiguity.

Lesson that this box teaches the hard way: a filtered TCP scan is a statement about the firewall.
It is not evidence that the host has no attack surface — and it says nothing at all about UDP.

---

## 1.2 The port the scan could not see

SNMP is UDP. `nmap -p 161` scans **TCP**/161 (the SNMP *trap* port), which is almost never what is
listening. The service we care about is `161/udp`:

```bash
sudo nmap -sU -p 161 --reason 192.168.103.145
```

On this box the answer was immediate and unambiguous — the agent replied to a hand-built request
even while every TCP port stayed filtered:

```bash
snmpget -v1 -c public -t 3 -r 1 -On 192.168.103.145 1.3.6.1.2.1.1.1.0
```

```
.1.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 25 Model 1 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 19041 Multiprocessor Free)"
```

That single line is the whole recon phase in miniature: the host is Windows, build **19041**, and it
will talk SNMP to anyone with the community string.

---

## 1.3 First mistakes, recorded honestly

Three commands were run before the working one. Each failure is a lesson, so they stay in.

**(a) No version specified.**

```bash
snmpwalk 192.168.103.145
```

```
snmpwalk: Timeout
```

Modern net-snmp defaults to **SNMPv3 noAuthNoPriv**. A v1/v2c agent has no idea what to do with a v3
message and drops it, so the result is a timeout that looks identical to "wrong community". Always
state the version explicitly.

**(b) Wrong script — a Linux tree on a Windows host.**

```bash
snmpwalk -v1 -c public 192.168.103.145 1.3.6.1.4.1.8072.1.3.2
```

```
End of MIB
```

`1.3.6.1.4.1.8072` is the **net-snmp** enterprise OID. `NET-SNMP-EXTEND-MIB` only exists on
Linux/Unix agents; Windows' built-in SNMP service returns end-of-tree. This is a *successful* walk
of an empty subtree, not a permission error. Replaying Linux `extend` tricks against a Windows host
always lands here.

**(c) Community guessing, badly.**

```bash
for c in kiero oscp oscp.exam student cl5 lab zachary public2 cisco; do
  printf "%-12s " "$c"
  snmpget -v1 -c "$c" -t 4 -r 0 192.168.103.145 1.3.6.1.2.1.1.5.0
done
```

```
kiero        Timeout: No Response
oscp         Timeout: No Response
oscp.exam    Timeout: No Response
student      Timeout: No Response
cl5          Timeout: No Response
lab          Timeout: No Response
zachary      Timeout: No Response
public2      Timeout: No Response
cisco        Timeout: No Response
```

Every one timed out — including the *working* community in a slightly different spelling. Wrong
communities are dropped silently per RFC, so a timeout tells you nothing except "not this one". Nine
guesses is also far too small a list to be meaningful; `onesixtyone` with a real wordlist is the
right tool when `public` genuinely fails.

Here `public` was already correct. The lesson is to confirm what you have before brute-forcing what
you don't.

---

## 1.4 What we entered the enumeration phase with

| Fact | Value | Why it matters |
|---|---|---|
| Reachable | SNMP UDP/161 only | the TCP firewall is host-side; SNMP was allowed deliberately |
| OS | Windows 10 **19041** (2004) | out of support since Dec-2021 → assume unpatched |
| Hostname | `zachary` | also `sysContact` → a human account name, not a service name |
| TCP | all filtered at scan time | do not conclude "no services" — re-verify later |
| RDP | 3389 filtered here, open later | port state on this box changed between snapshots |

Corroborated later in the session: `1978/tcp` went from `filtered` to `open` after the lab was
refreshed. **Re-scan before you write a port off.** A snapshot reverting a firewall rule is enough
to turn a dead box into a shell.
