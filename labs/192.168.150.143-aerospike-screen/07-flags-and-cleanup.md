# 07 — Flags & cleanup

## 7.1 Proof

```
root@lab-pwk2-student-cl4-143-ubuntu20-aero-242-100:~# id
uid=0(root) gid=0(root) groups=0(root)

root@...# cat /root/proof.txt
7fd0bd2e18b52d791a6600fbd8e622b7

root@...# cat /home/aero/local.txt
8d0b2414df3c73b491d05711c000a9d6
```

| Flag | Value | Held by |
|---|---|---|
| `local.txt` | `8d0b2414df3c73b491d05711c000a9d6` | `aero` (readable from the very first UDF call) |
| `proof.txt` | `7fd0bd2e18b52d791a6600fbd8e622b7` | `root` only |

Both flags are `33` bytes on disk, owned by the account that holds them, and `local.txt` is readable
by the service account that the vulnerable daemon runs as. That is worth noting: a box whose
database user can read `local.txt` gives up half its score to a single unauthenticated API call.

---

## 7.2 Removal

The engagement left four kinds of artefact. Three were removed; one is deliberate access.

**Removed — the escalation backdoor and scratch files:**

```bash
rm -f /tmp/screenroot/rbash        # setuid bash — the real risk if left behind
rm -f /tmp/screenroot/.lock
rm -f /tmp/f /tmp/sc.txt           # reverse-shell FIFO, process-watcher output
```

`/etc/ld.so.preload` **self-deleted** when the payload ran — verified:

```bash
ls -la /etc/ld.so.preload
```

```
ls: cannot access '/etc/ld.so.preload': No such file or directory
```

That is the `unlink()` in the constructor doing its job. Nothing to clean up there, but the check is
not optional: a leftover `/etc/ld.so.preload` pointing at a file you later delete bricks every
dynamic binary on the host.

**Left in place — a real setuid binary still exists:**

```
-rwsr-xr-x 1 root root 1860304 /usr/bin/screen-4.5.0
```

The vulnerability is *the installation*, not our exploit. Removing our `rbash` does not close the
hole; `screen-4.5.0` will do this again for anyone. The defensive fix is in §7.4.

**Left in place — root SSH key (access, by design):**

```bash
wc -c /root/.ssh/authorized_keys
```

```
91
```

One ed25519 key, added to get a TTY. Remove it when the report is written:

```bash
rm -f /root/.ssh/authorized_keys
```

**Left in place — harmless payload files:**

```
/tmp/screenroot/libhax.so        (no setuid, plain 0755)
/tmp/screenroot/rootcmd.sh
/tmp/screenroot/rootout.txt
/tmp/screenroot/exam_key.pub
```

None are executable as anything but `aero`, and none are referenced by the system any more
(`ld.so.preload` is gone).

**Left in place — the database side.** The UDF module `poc` is still registered, and the `put` calls
left records in `test.cve202013151`. Both are inert, but both are ours. Purge them:

```bash
python3 - <<'EOF'
import aerospike
c = aerospike.client({"hosts": [("192.168.150.143", 3000)]}).connect()
c.udf_remove("poc")
for k in c.scan("test", "cve202013151"):
    c.remove(("test", "cve202013151", k[2]))
c.close()
EOF
```

(On a real engagement, `udf_remove` and a truncated set are the first two lines of the cleanup
checklist. A UDF is code you installed on someone else's server.)

---

## 7.3 What actually mattered

Five things, in order of how much they changed the outcome:

1. **`filtered`, not `closed`.** The full scan hid 65525 ports and also hid `3002`, which belongs to
   the daemon we exploited. Reading that line correctly is why the port block got a second look.
2. **A tool's version gate is not evidence.** Exploit-DB 49067 refuses `5.1.0.0`+ and calls this box
   patched. The box is `5.1.0.1` against a fix in `5.1.0.3`. Four lines of client code beat a
   wrapper that fails closed for the wrong reason.
3. **`dpkg -l` describes a file that may not be the one on the path.** The screen *package* is
   `4.8.0-1ubuntu0.1`; the setuid binary is `4.5.0`. Every scanner that trusts the package database
   calls this host clean.
4. **CRLF is a real bug class.** screen logs terminal output, terminals use `\r\n`, and `ld.so`
   treats `\r` as part of the path. The exploit "worked" and did nothing, with only a warning to say
   so. `cat -A` is how you see it.
5. **No egress changes the whole workflow.** With no reverse shell and no `wget`, files move over
   whatever channel already exists — here, the database socket that gave code execution. That is
   slower and needs hash verification at every hop, but it is not optional.

---

## 7.4 Defensive notes

- **Aerospike: bind it and authenticate it.** Port 3000 had no authentication at all. Set
  `security { enable-security true }`, create users, and never expose 3000–3003 beyond the app
  subnet. In `5.1.0.3+` the Lua environment is sandboxed as well; that is the version to be on.
- **Treat `udf_put` as remote code execution by design.** It *is* an upload-and-run interface. Audit
  which accounts can register UDFs, and alert on new module names in production.
- **`/etc/ld.so.preload` should not exist.** On a normal host it is absent. Its presence is a
  compromise indicator; its *creation* by a setuid binary is the exploit. Monitor it with the same
  priority as `/etc/passwd`.
- **Never ship a setuid `screen`, let alone an old one.** `screen` has no legitimate reason to be
  setuid root. `chmod u-s /usr/bin/screen*`. If a tool must be setuid, it must also drop privileges
  before touching anything the caller controls — path, umask, or filename.
- **Version-managed ≠ as-installed.** Reconciliation between package metadata and on-disk binaries is
  the control that would have caught `screen-4.5.0`, and it is the control almost nobody runs.
- **`local.txt` was readable by the service account.** Flag placement is a design choice; placing it
  where a database daemon's user can reach it gives it away on the first foothold.

---

## 7.5 Corrections to the obvious reading

| Tempting conclusion | What was actually true |
|---|---|
| "Ports 3000/3001/3003 are `ppp`, `nessus`, `cgms`" | Those are nmap's fallback guesses. The block is Aerospike: service / fabric / (filtered info) / heartbeat. |
| "Aerospike 5.1.0.1 — the public exploit won't run, so it's patched" | The exploit's guard is wrong: `5.1.0.0` and `5.1.0.1` are both below the `5.1.0.3` fix. Driving the client directly works. |
| "`dpkg -l screen` says 4.8.0, so screen is patched" | The setuid binary is `screen-4.5.0`, symlinked as `/usr/bin/screen`. The package is not the program. |
| "PwnKit will land — `pkexec` is setuid" | `policykit-1 0.105-26ubuntu1.3` carries the fix. Refuted before spending time on it. |
| "Kernel 5.4 → Dirty Pipe" | CVE-2022-0847 needs 5.8+. Refuted by arithmetic. |
| "The root cron every minute is the intended path" | Plausible (`/opt/aerospike/bin` is `aero`-owned) but **not tested**. The setuid screen was deterministic; the cron is recorded as an alternate, not as solved. |
| "`screen -L` wrote the preload file, so it's done" | It wrote it with **CRLF**, and `ld.so` silently ignored every entry. The rewrite was required. |
| "The preload file is gone — the exploit failed" | The payload deletes it deliberately, to stop child processes re-entering `system()`. Absence is success. |
