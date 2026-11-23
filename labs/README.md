# Labs

One directory per lab. Each holds the markdown source, its evidence, and the generated
`index.html` that `main.html` links to.

| Lab | Target | Result | Walkthrough |
|---|---|---|---|
| [`192.168.245.149-kiero`](192.168.245.149-kiero/) | Ubuntu 20.04.5 — SNMP → FTP → setuid | root, both flags | [page](192.168.245.149-kiero/index.html) · [notes](192.168.245.149-kiero/README.md) |
| [`192.168.237.150-text4shell`](192.168.237.150-text4shell/) | Ubuntu 22.04.1 — CVE-2022-42889 + JDWP | root, both flags | [page](192.168.237.150-text4shell/index.html) · [notes](192.168.237.150-text4shell/README.md) |
| [`192.168.137.151-gust`](192.168.137.151-gust/) | Windows 10 21H2 — FreeSWITCH ESL `ClueCon` → GodPotato | SYSTEM, both flags | [page](192.168.137.151-gust/index.html) · [notes](192.168.137.151-gust/README.md) |
| [`ad-oscp-exam`](ad-oscp-exam/) | AD set — MS01 → MS02 → DC01 | MS01 SYSTEM, DC01 pending | [page](ad-oscp-exam/index.html) · [notes](ad-oscp-exam/README.md) |
| [`ad-oscp-ms02`](ad-oscp-ms02/) | AD set from `10.10.152.0/24` — DC01 direct, MS02 WinRM, MSSQL, BloodHound | MS02 foothold, DC01 open | [page](ad-oscp-ms02/index.html) · [notes](ad-oscp-ms02/README.md) |
| [`192.168.103.145-snmp-mouse`](192.168.103.145-snmp-mouse/) | Windows — SNMP → Mouse Server CVE-2022-3218 → PrintNightmare | SYSTEM, both flags | [page](192.168.103.145-snmp-mouse/index.html) · [notes](192.168.103.145-snmp-mouse/README.md) |
| [`192.168.161.144-git-exposure`](192.168.161.144-git-exposure/) | Ubuntu 22.04.1 — `.git` leak → credential reuse → CVE-2023-0386 | root, both flags | [page](192.168.161.144-git-exposure/index.html) · [notes](192.168.161.144-git-exposure/README.md) |
| [`192.168.150.143-aerospike-screen`](192.168.150.143-aerospike-screen/) | Ubuntu 20.04.4 — Aerospike CVE-2020-13151 → setuid screen 4.5.0 | root, both flags | [page](192.168.150.143-aerospike-screen/index.html) · [notes](192.168.150.143-aerospike-screen/README.md) |

The hub for all of these is [`../main.html`](../main.html).

## Adding a lab

1. `mkdir labs/<name>` and drop in `README.md` plus numbered chapters
   (`01-reconnaissance.md`, `02-…`).
2. Add one entry to `LABS` in `../build.py` — `out` is `LABS_DIR / "<name>" / "index.html"`,
   `home` is `"../../main.html"`, and `chapters` lists the markdown in order.
3. Run `python3 build.py`. It writes `labs/<name>/index.html`, rebuilds `main.html`, and prints a
   warning for any folder under `labs/` that has no `LABS` entry.

Every lab gets a card and a `<select>` option on `main.html` automatically, so the picker always
covers the whole repository.
