# 05 — What this set teaches

The value of this set is not the commands — it is the order in which they are used. Each step below is
a decision that saved time, and each one generalises to the next AD box.

## 5.1 Order of work

- **AD first.** It is a chain of small, well-signposted steps and it carries a large share of the
  points. Doing it while fresh beats doing it at hour 20.
- The initial `nmap` is not the scoring event, but keep it: the report needs the scan, and the
  service list is what tells you this is a WinRM box.
- The exam hands you one credential at the start. Spend the first five minutes validating it against
  **SMB then WinRM** — that is the whole foothold decision on this set.

## 5.2 Do not fall into the database

- A bcrypt table on a workstation is **loot, not a path**. Note it, save the output, move on.
- If you ever do crack, do it on the Windows host (or with hashcat on the GPU box) and in the
  background — never sit and watch it.
- The fastest win on this box was not the web app at all: it was `winPEAS` reading an environment
  variable.

## 5.3 winPEAS early

Run it immediately after the first shell, before custom enumeration. The finding here is a
machine-level environment variable containing the local Administrator password — the kind of thing a
hand-written enumeration script will miss if you only look at services and ACLs.

## 5.4 Proof handling (the part people lose points on)

The report is scored as much as the shell. Capture each flag while you are still on the host that
holds it, and capture it in a way that survives scrutiny:

1. One image per flag that shows **the command, the output, and the host** together
   (`hostname`, `whoami`, `ipconfig`, then `type proof.txt`).
2. The same content **copy-pasted as text** into the report — graders want to copy commands.
3. Do it at the moment you get the flag, not at the end from memory.

An image of a flag without the command and hostname beside it is exactly the kind of evidence a grader
can dispute.

## 5.5 Tunneling

- ligolo-ng here; chisel is equally acceptable — the exam does not reward the tool.
- **One** route into `172.16.91.0/24` is the requirement. No double pivot, no proxy chains.
- Start the tunnel as soon as you have local admin, before you need it. It costs two minutes and
  removes a whole class of "why can't I reach the DC" confusion.

## 5.6 With local admin, dump before you leave

- Local admin on the dual-homed box is the **collection point**: LSASS/LSA on WS01 held a domain
  credential in cleartext.
- `nxc … -M lsassy` (or `secretsdump.py`) is a two-minute step that often replaces an hour of
  guessing on the next host. Do it before pivoting away.

## 5.7 Checklist distilled

| Phase | Command | Done |
|---|---|---|---|
| Validate creds | `nxc smb <ip> -u user -p pass` | ☐ |
| Shell | `nxc winrm …` / `evil-winrm` | ☐ |
| Local config | `cat config.php`, MySQL tables | ☐ |
| Privesc | `winPEASx64.exe` → env vars | ☐ |
| Admin check | `nxc smb … --local-auth` | ☐ |
| Proof | `hostname; whoami; type proof.txt` in one image | ☐ |
| Second NIC | `ipconfig` | ☐ |
| Tunnel | ligolo-ng `start` + `ip route add` | ☐ |
| Loot | `nxc … -M lsassy` / `secretsdump` | ☐ |
