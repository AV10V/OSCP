# 04 — SSH into the second Linux host, then Nexus on 8005

The mailbox credentials open SSH on a **different** machine: an Ubuntu server running Sonatype
Nexus, with its install directory readable and a web UI on a non-default port.

## 4.1 SSH

```bash
ssh <dev-user>@192.168.91.110
```

```
The authenticity of host '192.168.91.110 (192.168.91.110)' can't be established.
ED25519 key fingerprint is SHA256:...
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.91.110' (ED25519) to the list of known hosts.
```

The MOTD identifies the host:

```
Ubuntu 24.04 LTS
...
  System load:  ...
  Usage of /:   ...
  Memory usage: ...
  Swap usage:   ...
  Processes:    ...
  Users logged in: ...

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

*** System restart required ***
```

```
$ uname -a
Linux ... 6.8.0-31-generic #31-Ubuntu SMP ... x86_64 GNU/Linux
```

Two things to note before anything else:

| Observation | Consequence |
|---|---|
| Ubuntu 24.04, kernel 6.8 | recent — no kernel privesc by default |
| a **second** host, not `.119` | the mail server is a credential source, not the target |
| `ifconfig` shows `eth0 … 192.168.91.0/24` | same flat network as the rest of the set |

## 4.2 Enumeration: linpeas

```bash
./linpeas.sh
```

LinPEAS flagged the Nexus folder as accessible and pointed at the service on port 8005.

The relevant LinPEAS section is the **file-permission / interesting-files** block:

```
Files with permissions ...
... root and readable by me but not world readable (T1082)

/opt/nexus/nexus-3.x.x/etc/...
/opt/nexus/nexus-3.x.x/bin/nexus
/opt/nexus/nexus-3.x.x/etc/nexus.properties
...
```

| Finding | Meaning |
|---|---|
| `/opt/nexus/nexus-3.x.x/` | Sonatype Nexus Repository installed locally |
| files **readable by the current user** but not world-readable | the account was given access to the Nexus install — and that is unusual |
| a listener on **8005** | the Nexus UI/API is bound on a non-default port |

Why "readable by me but not world readable" matters: it is a deliberate permission set. Someone added
this account to the group that owns the Nexus directory. That is a privilege you did not have on the
mail server, and it is usually the pivot to the application's own credentials
(`nexus.properties`, the admin password file, or the repository blob store).

## 4.3 Nexus on 8005

The Nexus web interface answers with an **Authentication** dialog:

```
Nexus Repository - ...
Authentication
Username:
Password:
```

Nexus's default port is 8081, so `8005` is a deliberate choice by the box author — either to move it
off the well-known port or because something else already holds 8081.

The next steps on this host:

1. Read the Nexus configuration the account can now see (`etc/nexus.properties`, the admin password
   file under `etc/`, or the `sonatype-work` directory).
2. Log in to `http://192.168.91.110:8005/` with those credentials.
3. Use the repository manager the way the box intends — a deployable artifact, a scheduled task, or a
   script repository pointing at the host itself.

## 4.4 Open questions

| Question | Status |
|---|---|
| The SSH username and password | only the username `james` is certain |
| Whether `.110` is Linux 1 or Linux 2 of the set | the working directory is `…/SECOND`, and `.119` is `…/FIRST`, which suggests `.110` is the second box |
| Whether a flag was captured on `.119` | no `local.txt` found; `proof.txt` on `.110` is covered in [`05-nexus-root.md`](05-nexus-root.md) |
| Root on `.119` | not obtained |
| The Nexus exploit itself | covered in [`05-nexus-root.md`](05-nexus-root.md) |

One unverified line appears in a terminal scrollback:
`[22][ssh] host: 192.168.91.119 login: root password: toor`. It is small and partially obscured, so
it is noted as **unconfirmed** rather than as a step. If it is real, it is a second, independent
way into the mail host and worth testing first in a re-run.

---

**Next:** [`05-nexus-root.md`](05-nexus-root.md) — the API key, the file read, and root.
