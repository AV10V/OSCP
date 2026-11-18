# 06 — Flags

Both flags read, with the account that read them recorded next to each value. That distinction is the
point: `local.txt` is not a privilege boundary on this box, `proof.txt` is.

| Flag | Path | Read as | Value |
|---|---|---|---|
| `local.txt` | `C:\Users\chris\Desktop\local.txt` | `OSCP\chris` | `9d05eefc0447258ceab32e91e3b54aac` |
| `proof.txt` | `C:\Users\Administrator\Desktop\proof.txt` | `NT AUTHORITY\SYSTEM` | `46586fc8f483adc13d76335768bf0a4c` |

---

## 6.1 `local.txt` — as `chris`

The user flag is on the account's own desktop and readable through the event socket. The wrapper
output for that read:

**On Kali**

```bash
python3 1.py 192.168.137.151 "type C:\Users\chris\Desktop\local.txt 2>&1"
```

```
Authenticated
Content-Type: api/response
Content-Length: 33

9d05eefc0447258ceab32e91e3b54aac
```

`Content-Length: 33` for a 32-character value: the extra byte is the newline, so nothing was
concatenated or truncated by the wrapper. No escalation, no shell — the foothold alone is enough for
this half.

## 6.2 `proof.txt` — as SYSTEM

The administrator's desktop is ACL'd away from `chris` (`Access is denied`, chapter 05). Two
independent routes were used to read it, and they agree:

**Route 1 — GodPotato copying the file, then reading the copy as `chris`:**

```
46586fc8f483adc13d76335768bf0a4c
```

**Route 2 — `type` inside the SYSTEM `cmd.exe` on port 4448:**

```
C:\Windows\system32>type C:\Users\Administrator\Desktop\proof.txt
46586fc8f483adc13d76335768bf0a4c
```

Two different mechanisms, one value. The first proves the *file* was readable with a SYSTEM token;
the second proves an *interactive shell* has that token. Either would be sufficient on its own, and
having both removes any doubt about which account performed the read.

The exact command used for route 1 is reproduced in full in [chapter 05](05-privilege-escalation.md),
because the reading half (`type ... proof_out.txt` executed as `chris`) is the part that makes it
evidence rather than a claim.

## 6.3 What "root" means on Windows

There is no `root` account on this box. The equivalent is `NT AUTHORITY\SYSTEM`, and it was reached
through a token, not a password — so nothing about the escalation survives a reboot, and no
credential was obtained that would work on another host.

Worth stating explicitly for the report: the box was not owned by cracking a password, exploiting a
memory-corruption bug, or finding a local administrator in a group. It was owned by a **default
password on an administrative interface**, then by a **privilege the service account already held**.

→ [07 — Cleanup and lessons](07-cleanup-and-lessons.md)
