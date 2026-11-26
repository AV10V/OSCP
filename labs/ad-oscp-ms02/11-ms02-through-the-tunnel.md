# 11 — MS02 through the tunnel

MS02 is the host pass 2 spent six chapters on. In this pass it is reachable through the tunnel
for the first time, so it gets a full scan — and then the pass walks past it. This chapter records
what it exposed, the clock problem it created, and why it was not the way in.

---

## 11.1 The scan

```bash
nmap -p- -T4 --min-rate 10000 --max-retries 2 -n -Pn -sC -sV -A 10.10.131.148
```

```
Nmap scan report for 10.10.131.148
Host is up (0.056s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC

Host script results:
|_clock-skew: 26m04s
|_nbstat: NetBIOS name: MS02, NetBIOS user: <unknown>, NetBIOS MAC: fa:16:3e:3c:33:5f (unknown)
| smb2-time:
|   date: 2026-11-26T05:18:26
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 228.09 seconds
```

The retransmission warning and the timing-stats lines are omitted. The host drops everything
else — consistent with a host firewall — which is why `65528` ports are `filtered` rather than
`closed` and why the scan took nearly four minutes.

---

## 11.2 Reading the ports

| Port | Service | What it means here |
|---|---|---|
| `135`, `49664`, `49667` | MSRPC | endpoint mapper and dynamic RPC — enumeration surface, no credential |
| `139`, `445` | SMB | file sharing; signing **enabled but not required** |
| `5040` | unknown | a Windows service port; not enough banner to identify it |
| `5985` | WinRM | a shell for anyone in `Remote Management Users` |

Two negatives are as useful as the positives:

**No `1433`.** The MSSQL service that pass 2 built chapters 03 and 07 around is not exposed in
this instantiation. The SQL path does not exist here.

**No credential was tested against MS02.** The capture contains no SMB, WinRM or MSSQL
authentication attempt — this chapter is enumeration only. Whether `celia.almeda`, `web_svc` or
the cracked local Administrator would authenticate here is **not established**.

`signing enabled but not required` is the one configuration worth flagging: it makes MS02 a valid
relay target in principle. Nothing was coerced into authenticating during this pass, so it stayed
a note rather than a path.

---

## 11.3 The 26-minute clock

`nmap` reports `clock-skew: 26m04s`, and `smb2-time` puts the host at
`2026-11-26T05:18:26Z` while Kali is at `2026-11-25 20:49 PST`. Kerberos rejects any request
more than five minutes off the KDC, so every Kerberos operation will fail until this is fixed.

The obvious tools did not work:

```bash
sudo rdate -n 10.10.131.148
```

```
rdate: Not enough valid responses received in time
rdate: Unable to get a reasonable time estimate
```

```bash
sudo ntpdate -u 10.10.131.148
```

```
ntpdig: no eligible servers
```

`ntpdate` is `ntpdig` on this Kali, and MS02 is not offering time service on the query port. With
the target unreachable as a time source, the clock was moved by hand:

```bash
sudo date -s "$(date -d '+0 hour 26 minutes 04 seconds' '+%Y-%m-%d %H:%M:%S')"
```

```
Wed Nov 25 09:21:36 PM PST 2026
```

That aligns Kali with the host to within a few seconds. It is a lab workaround, not a fix: the
clock will drift again, and on a real engagement setting the system time by hand can break
tickets, logs and file timestamps in ways that are harder to diagnose than the skew. Prefer a
reachable NTP source, or correct only the offset when the tooling allows it.

---

## 11.4 Why MS02 was not the way in

MS02 was reachable, enumerated, and left alone. That is not an oversight — the credential that
finishes the set was already in hand:

- the DCC2 entry in chapter 09 is the **domain** Administrator, so it applies to DC01 directly;
- MS02 exposed no SQL service and no credential of ours was known to work there;
- attacking MS02 would have added a hop, not removed one.

Pass 2 reached the opposite conclusion for a different position: with DC01 direct, MS02 was the
only host whose token could be escalated, so `sql_svc` was the plan. Here the plan is unnecessary
— and that is the useful comparison. The "second hop" is not always on the path.

| Host | Address | State after this chapter |
|---|---|---|
| MS01 | `10.10.131.147` | SYSTEM, local admin add in place |
| MS02 | `10.10.131.148` | reachable · enumerated · **not attacked** |
| DC01 | `10.10.131.146` | not contacted yet — credential in hand |

DC01 is next.
