# Labs

One directory per lab. Each holds the markdown source, its evidence, and the generated
`index.html` that `main.html` links to.

| Lab | Target | Result | Walkthrough |
|---|---|---|---|
| [`192.168.245.149-kiero`](192.168.245.149-kiero/) | Ubuntu 20.04.5 — SNMP → FTP → setuid | root, both flags | [page](192.168.245.149-kiero/index.html) · [notes](192.168.245.149-kiero/README.md) |
| [`192.168.237.150-text4shell`](192.168.237.150-text4shell/) | Ubuntu 22.04.1 — CVE-2022-42889 + JDWP | root, both flags | [page](192.168.237.150-text4shell/index.html) · [notes](192.168.237.150-text4shell/README.md) |
| [`ad-oscp-exam`](ad-oscp-exam/) | AD set — MS01 → MS02 → DC01 | MS01 SYSTEM, DC01 pending | [page](ad-oscp-exam/index.html) · [notes](ad-oscp-exam/README.md) |

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
