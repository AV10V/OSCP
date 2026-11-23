# 02 — Mobile Mouse, and CVE-2023-31902

Goal: decide whether the product on 9099 is exploitable, and understand *how* it executes commands
before touching the target.

---

## 2.1 What the product is

Mobile Mouse turns a phone into a wireless mouse and keyboard. The Windows-side **Mobile Mouse
Server** listens on **TCP 9099** for the control protocol and **35913** for WebSocket clients. By
default it has **no password**, and it injects whatever it receives into the interactive desktop.

| Field | Value |
|---|---|
| Product | Mobile Mouse Server (RPA Technology) |
| Version on host | **3.6.4** — read from `InstalledProducts` in chapter 04 |
| Control | 9099/tcp — unauthenticated |
| WebSocket | 35913/tcp |
| CVE | **CVE-2023-31902** — pre-auth RCE, CVSS 9.8 |
| Module | `exploit/windows/misc/mobile_mouse_rce` |

## 2.2 Confirm the exploit exists

```bash
searchsploit mobile mouse
msfconsole -q -x "search mobile_mouse_rce; exit"
```

```
Exploit: Mobile Mouse 3.6.0.4 - Remote Code Execution (RCE)
         EDB-ID 51010
```

> **Version caveat.** The published exploit targets **3.6.0.4 and below**. This host runs **3.6.4**
> and the module still worked — the protocol did not change between those builds. Treat a version
> range as a hint about *where to look*, then prove it against the actual host.

## 2.3 The mechanism — a keyboard, not a memory bug

There is no buffer overflow and no deserialisation gadget. The server is a keyboard: given a
message, it types. The Metasploit module uses that to:

1. open a command prompt on the interactive desktop,
2. run `certutil` to download a payload from an attacker-hosted HTTP server (`SRVHOST`),
3. stage it in `C:\Windows\Temp\` and execute it.

Two consequences follow directly from that design, and both shape the rest of the box:

- **The shell is whoever is logged in.** The server does not elevate; it types as the session owner.
  Expect a standard user, not SYSTEM.
- **It needs a live desktop session.** If nobody is logged on, there is no window to type into. The
  Seatbelt output in chapter 04 confirms the session exists (`explorer.exe`, `dwm.exe` running for
  `OSCP\Tim`).

## 2.4 Preconditions, stated before firing

| Precondition | Evidence | If absent |
|---|---|---|
| Vulnerable build **installed** | `InstalledProducts` → Mobile Mouse 3.6.4 | nothing to attack |
| Server **listening** | nmap 9099 open, banner `Mobile Mouse Server` | installed-but-dead |
| **No password** set | default configuration; the module requires it | the client-side PIN blocks injection |
| Interactive desktop session | `OSCP\Tim` logged on, shell earlier in `C:\Users\Tim` | keystrokes land nowhere |

The first three were answered from Kali, before any shell. The fourth is the one that bites on
servers — and it is the reason a "critical, 9.8" RCE is a much smaller problem on a locked-down host.
