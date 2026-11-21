# 02 — SNMP enumeration

Goal: turn one working community string into an inventory — identity, processes, software, users —
and read that inventory the way you would read a shell's `tasklist`.

---

## 2.1 Confirm the agent and the version

```bash
snmpwalk -v1 -c public -On 192.168.103.145 1.3.6.1.2.1.1
```

```
.1.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 25 Model 1 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 19041 Multiprocessor Free)"
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.311.1.1.3.1.1
.1.3.6.1.2.1.1.3.0 = Timeticks: (287801) 0:47:58.01
.1.3.6.1.2.1.1.4.0 = STRING: "zachary"
.1.3.6.1.2.1.1.5.0 = STRING: "zachary"
```

Four readings, in order of usefulness:

- **`sysObjectID` under `1.3.6.1.4.1.311`** = Microsoft. This is the Windows extension agent, not a
  network device — so no Cisco-style config-download tricks, and no `8072` extend tree.
- **Build 19041** = Windows 10 2004. Windows SNMP always reports kernel `6.3` for Win10/11, so the
  *build number* is your only OS-version signal. It cannot show patch level — you find that out with
  a local tool later.
- **Uptime `0:47:58`** — freshly booted. On a lab box that means a snapshot was restored, so
  anything you plant dies at revert.
- **`sysContact` = `sysName` = `zachary`.** Not a service name. A human one. Keep it: it is a
  candidate account for SMB/WinRM/RDP if the shell route ever needs a fallback.

Always add `-On` (numeric OIDs). MIB-name rendering differs between installs and silently breaks
parsing later.

---

## 2.2 Processes — `hrSWRunTable`

```bash
snmpwalk -v1 -c public 192.168.103.145 1.3.6.1.2.1.25.4.2.1.2 \
  | sed -E 's/.*STRING: //' | sort -u
```

47 entries. The ones that mattered:

| Process | Reading |
|---|---|
| `MouseServer.exe` | the remote-control server, running as a logged-on user |
| `Mouse Server Luminati.exe` | same product, Luminati SDK build — a proxy-resale variant |
| `explorer.exe`, `dwm.exe`, `sihost.exe`, `SearchApp.exe`, `StartMenuExperienceHost.exe` | **an interactive desktop session is live** |
| `w3wp.exe` | IIS application-pool worker — a web app exists on some port |
| `MsMpEng.exe`, `MpDefenderCoreService.exe`, `SecurityHealthService.exe` | Defender is fully active |
| `spoolsv.exe` | Print Spooler loaded → PrintNightmare is on the table later |
| `qemu-ga.exe`, `VGAuthService.exe`, `vm3dservice.exe`, `blnsvr.exe` | KVM guest with VMware Tools and virtio balloon — a lab VM |
| `snmp.exe` | the service we are talking to |

The second row is the single most valuable observation on this box. `MouseServer.exe` tells you
*what* to attack; `explorer.exe` + `dwm.exe` + `sihost.exe` tell you the attack **will work**.
Keystroke injection needs a desktop to type into — on a headless server the same exploit connects
and does nothing observable.

---

## 2.3 Installed software — `hrSWInstalledTable`

```bash
snmpwalk -v1 -c public 192.168.103.145 1.3.6.1.2.1.25.6.3.1.2 \
  | sed -E 's/.*STRING: //' | sort -u
```

```
"Cloudbase-Init 1.1.6"
"Microsoft Edge"
"Microsoft Edge WebView2 Runtime"
"Microsoft Update Health Tools"
"Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.24.281"
"Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.24.281"
"Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127"
"Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127"
"Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127"
"Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127"
"Mouse Server version 1.7.8.5"
"PuTTY release 0.76 (64-bit)"
"QEMU guest agent"
"Red Hat QXL controller"
"Spice Agent 0.10.0-5 (64-bit)"
"Update for Windows 10 for x64-based Systems (KB5001716)"
"Virtio-win-driver-installer"
"Virtio-win-guest-tools"
"VMware Tools"
```

| Entry | Reading |
|---|---|
| `Mouse Server version 1.7.8.5` | **the vulnerable package** — see chapter 03 |
| `Cloudbase-Init 1.1.6` | OpenStack guest agent; its log often contains the image's injected password |
| `PuTTY release 0.76` | old SSH client; saved sessions leak hostnames/usernames, not passwords |
| `VMware Tools`, `Virtio-win`, `QEMU guest agent`, `Spice Agent`, `Red Hat QXL` | confirms the KVM/QEMU lab platform |
| `KB5001716` | an update *stub* — tells you nothing about the cumulative patch level |

That last row is a trap worth naming: a single `KB` entry in this table is **not** a patch level.
SNMP on Windows exposes no hotfix list, no registry, no file system, and no domain membership.

---

## 2.4 Users, services, shares — LAN Manager MIB II

```bash
snmpwalk -v1 -c public -On 192.168.103.145 1.3.6.1.4.1.77.1.2.25
```

The table is indexed by the **ASCII codes** of the account name, so it comes back as
`…svUserName.5.71.117.101.115.116 = STRING: "Guest"`. Decode rather than squint:

```bash
snmpwalk -v1 -c public -On 192.168.103.145 1.3.6.1.4.1.77.1.2.25 \
  | sed -E 's/.*svUserName\.(([0-9]+\.?)+) = STRING: //' \
  | while read -r n; do echo "$n" | awk -F. '{for(i=2;i<=NF;i++) printf "%c", $i; print ""}'; done
```

On this host the table was sparse, and `svShareTable` (`1.3.6.1.4.1.77.1.2.27`) returned nothing —
which is the normal Windows behaviour, not a permissions problem. **Never report "no shares" from
SNMP.** Use SMB (`netexec smb … --shares`) once you have any credential.

---

## 2.5 The dead end, kept for the lesson

```bash
snmpwalk -v1 -c public 192.168.103.145 1.3.6.1.4.1.8072.1.3.2
```

```
End of MIB
```

```bash
snmpget -v1 -c public 192.168.103.145 1.3.6.1.4.1.8072.1.3.2.4.1.3.5.82.69.83.69.84
```

```
Error in packet
Reason: (noSuchName) There is no such variable name in this MIB.
Failed object: iso.3.6.1.4.1.8072.1.3.2.4.1.3.5.82.69.83.69.84
```

Decode that index: `5` = length, then `82 69 83 69 84` = **`RESET`**. This is the Linux
`extend RESET /usr/bin/…` pattern from countless OSCP writeups — an `extend` entry whose cached
output (`nsExtendOutput*`) leaks command output, sometimes run as root.

On a Windows host the entire `8072` tree is empty, because it is not net-snmp. Two signals said so
before the walk: `sysObjectID` was `1.3.6.1.4.1.311` (Microsoft), and `sysDescr` was Windows. Once
you know the agent is Microsoft's, stop trying Linux playbooks.

| Signal | Microsoft agent | net-snmp agent |
|---|---|---|
| `sysObjectID` | `1.3.6.1.4.1.311.*` | `1.3.6.1.4.1.8072.*` |
| `8072.1.3.2` extend tree | empty | populated, output cached |
| `hrSWRunTable` | full process list | sparse/absent |
| `hrSWInstalledTable` | full software list | usually absent |

---

## 2.6 What the enumeration produced

```
UDP/161 public
  ├─ build 19041, host "zachary", up 48 min
  ├─ Mouse Server 1.7.8.5 installed        ← vulnerable version
  ├─ MouseServer.exe running               ← vulnerable service is live
  ├─ explorer.exe + dwm.exe + sihost.exe   ← interactive desktop ⇒ keystrokes land
  ├─ w3wp.exe                              ← an IIS site exists somewhere
  ├─ spoolsv.exe                           ← PrintNightmare candidate for later
  └─ Defender active                       ← expect payload quarantine
```

That is a complete attack plan without a single packet sent to a service port. Chapter 03 turns it
into a decision.
