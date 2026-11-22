#!/usr/bin/env python3
"""
Build a single self-contained interactive HTML site from the markdown walkthrough.

    python3 build.py      ->  main.html (lab index) + labs/<dir>/index.html (one page per lab)

No external assets, no CDN, no build tooling. Everything (CSS, JS, content) is inlined so the
page works offline, from a file:// path, and on GitHub Pages.
"""
import re
import html
import pathlib
import datetime

import markdown
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.formatters import HtmlFormatter
from pygments.util import ClassNotFound

ROOT = pathlib.Path(__file__).parent
REPO = "https://github.com/AV10V/OSCP"
DOCS = ROOT / "docs"

LABS_DIR = ROOT / "labs"
KIERO = LABS_DIR / "192.168.245.149-kiero"
T4S = LABS_DIR / "192.168.237.150-text4shell"
AD = LABS_DIR / "ad-oscp-exam"
GUST = LABS_DIR / "192.168.137.151-gust"
WINSNMP = LABS_DIR / "192.168.103.145-snmp-mouse"
GITEXP = LABS_DIR / "192.168.161.144-git-exposure"
AERO = LABS_DIR / "192.168.150.143-aerospike-screen"

# Lab index: one card per lab, plus a select that redirects to that lab page.
# main.html is the entry point; index.html is a redirect so the Pages root keeps working.
HOME_OUT = ROOT / "main.html"
REDIRECT_OUT = ROOT / "index.html"

# Shared reference chapters, appended to every machine page (ids ch-08 / ch-09).
REFERENCE = [
    ("ch-08", "08", "Methodology", "The repeatable per-box loop", DOCS / "methodology.md"),
    ("ch-09", "09", "Cheat sheet", "Every command, with the flag that matters", DOCS / "cheatsheet.md"),
]

# ---------------------------------------------------------------------------
# One entry per lab. Each gets its own self-contained page built from the markdown
# in its directory; main.html links them all and redirects on selection.
# ---------------------------------------------------------------------------
LABS = [
    {
        "slug": "kiero",
        "out": KIERO / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "UDP/161 SNMP extend leak → default FTP credentials → exposed SSH key → "
                       "setuid PATH hijack → root.",
            "tags": ["Ubuntu 20.04", "SNMP", "FTP", "SUID"],
            "foot": "local.txt + proof.txt",
        },
        "dir": KIERO,
        "dir_rel": "labs/192.168.245.149-kiero",
        "ip": "192.168.245.149",
        "name": "kiero",
        "title": "192.168.245.149 — kiero · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: SNMP extend leak to default FTP "
                "credentials to a setuid PATH hijack. Full commands, reasoning and raw output.",
        "ogdesc": "UDP/161 SNMP leak → default FTP credentials → exposed SSH key → setuid PATH hijack → root.",
        "lede": "A Linux box whose only TCP services were three well-patched daemons — and whose entire "
                "entry point was hiding in a UDP port nobody scans. The host names its own weak credential "
                "over SNMP, then a setuid helper hands over root.",
        "badges": [
            ("", "Ubuntu 20.04.5"),
            ("", "vsftpd 3.0.5"),
            ("", "OpenSSH 8.2p1"),
            ("", "Apache 2.4.41"),
            ("warn", "udp/161 snmpd"),
            ("ok", "root · 2 flags"),
        ],
        "meta": [
            ("Host", "kiero"),
            ("IP", "192.168.245.149"),
            ("OS", "Ubuntu 20.04.5"),
            ("TCP", "21, 22, 80"),
            ("UDP", "161"),
            ("Result", "root"),
        ],
        "flags": [
            ("local.txt · as john", "af540ac8ffa61d312756f2f4a3877d1d"),
            ("proof.txt · as root", "9e7f4ce50acc525d577abfc26aebfd1e"),
        ],
        "chain": [
            ("01", "UDP 161", "snmpd · community <code>public</code>", "#ch-01"),
            ("02", "Extend leak", "<code>nsExtendTable</code> → username + default password", "#ch-03"),
            ("03", "FTP", "<code>kiero:kiero</code> → <code>id_rsa</code>", "#ch-04"),
            ("04", "SSH", "key → shell as <code>john</code>", "#ch-05"),
            ("05", "SUID", "<code>RESET_PASSWD</code> calls <code>system()</code>", "#ch-06"),
            ("06", "root", "<code>proof.txt</code>", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Port scan and service fingerprint",
             KIERO / "01-reconnaissance.md"),
            ("ch-02", "02", "Web enumeration", "The dead end, justified with four negatives",
             KIERO / "02-web-enumeration.md"),
            ("ch-03", "03", "SNMP", "The leak that hands over credentials", KIERO / "03-snmp.md"),
            ("ch-04", "04", "FTP", "Default credentials and exposed SSH keys", KIERO / "04-ftp.md"),
            ("ch-05", "05", "Foothold", "Shell as john, then local enumeration", KIERO / "05-foothold.md"),
            ("ch-06", "06", "Privilege escalation", "setuid + system() = PATH hijack",
             KIERO / "06-privilege-escalation.md"),
            ("ch-07", "07", "Flags &amp; cleanup", "Proof, tidy-up, lessons", KIERO / "07-flags-and-cleanup.md"),
        ] + REFERENCE,
    },
    {
        "slug": "text4shell",
        "out": T4S / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-text4shell",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "Blind Commons Text RCE (CVE-2022-42889) in a Spring Boot API, then an "
                       "unauthenticated JDWP agent on a root JVM.",
            "tags": ["Ubuntu 22.04", "Spring Boot", "Text4Shell", "JDWP"],
            "foot": "local.txt + proof.txt",
        },
        "dir": T4S,
        "dir_rel": "labs/192.168.237.150-text4shell",
        "ip": "192.168.237.150",
        "name": "text4shell",
        "title": "192.168.237.150 — text4shell · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: a blind Apache Commons Text RCE "
                "(CVE-2022-42889) in a Spring Boot search API, then unauthenticated JDWP on a root JVM. "
                "Full commands, reasoning and raw output.",
        "ogdesc": "Spring Boot /search → Text4Shell RCE as dev → unauthenticated JDWP on "
                  "127.0.0.1:8000 → root.",
        "lede": "A Spring Boot search API that interpolates its query parameter and returns nothing to "
                "show for it — the bug only appears out of band. The shell it yields is unprivileged, but "
                "a root JVM on the same host is listening for a debugger.",
        "badges": [
            ("", "Ubuntu 22.04.1"),
            ("", "OpenJDK 11.0.16"),
            ("", "Spring Boot"),
            ("warn", "commons-text 1.8"),
            ("warn", "jdwp 127.0.0.1:8000"),
            ("ok", "root · 2 flags"),
        ],
        "meta": [
            ("Host", "lab-pwk2-…-150-187"),
            ("IP", "192.168.237.150"),
            ("OS", "Ubuntu 22.04.1"),
            ("TCP", "22, 5000, 8080"),
            ("Loopback", "8000"),
            ("Result", "root"),
        ],
        "flags": [
            ("local.txt · as dev", "6851d85c0e1e82991b98fa6e146532fd"),
            ("proof.txt · as root", "43d31153587be5031d1db3f9a934eb46"),
        ],
        "chain": [
            ("01", "8080", "Spring Boot search API", "#ch-01"),
            ("02", "Blind", "<code>query</code> echoed, result always empty", "#ch-02"),
            ("03", "Text4Shell", "<code>${script:…}</code> → code in the JVM", "#ch-03"),
            ("04", "dev", "reverse shell · <code>local.txt</code>", "#ch-04"),
            ("05", "JDWP", "root JVM on <code>127.0.0.1:8000</code>", "#ch-05"),
            ("06", "root", "<code>proof.txt</code>", "#ch-06"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Three ports, one input surface",
             T4S / "01-reconnaissance.md"),
            ("ch-02", "02", "Web enumeration", "One route, one parameter, no feedback",
             T4S / "02-web-enumeration.md"),
            ("ch-03", "03", "Text4Shell", "CVE-2022-42889, proved blind", T4S / "03-text4shell.md"),
            ("ch-04", "04", "Foothold", "Shell as dev via ProcessBuilder", T4S / "04-foothold.md"),
            ("ch-05", "05", "Host enumeration", "The root JVM on port 8000", T4S / "05-enumeration.md"),
            ("ch-06", "06", "Privilege escalation", "JDWP breakpoint → root",
             T4S / "06-privilege-escalation.md"),
            ("ch-07", "07", "Flags &amp; cleanup", "Proof, tidy-up, lessons",
             T4S / "07-flags-and-cleanup.md"),
        ] + REFERENCE,
    },
    {
        "slug": "oscp-exam",
        "out": AD / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-oscp-exam",
        "card": {
            "status": "warn",
            "status_text": "in progress",
            "role": "MS01 → MS02 → DC01",
            "summary": "WinRM foothold on MS01 → SeImpersonate → SYSTEM → chisel pivot into "
                       "10.10.118.0/24 → MS02 → DC01.",
            "tags": ["Server 2019", "Active Directory", "SeImpersonate", "chisel"],
            "foot": "MS01 SYSTEM · flag pending",
        },
        "dir": AD,
        "dir_rel": "labs/ad-oscp-exam",
        "ip": "10.10.118.0/24",
        "name": "oscp.exam",
        "title": "oscp.exam — MS01 → MS02 → DC01 · OSCP walkthrough",
        "desc": "Interactive walkthrough of an OSCP Active Directory set: a WinRM foothold on MS01, "
                "SeImpersonate to SYSTEM, a chisel SOCKS pivot into 10.10.118.0/24, then MS02 and DC01.",
        "ogdesc": "OSCP\\eric.wallows → WinRM → SeImpersonate → SYSTEM → chisel pivot → MS02 → DC01.",
        "lede": "A domain behind a dual-homed member server. Kali can reach exactly one host; the DC "
                "lives on a network only MS01 can see. The way in is a domain user with "
                "SeImpersonatePrivilege — which is enough to take the host and open the tunnel.",
        "badges": [
            ("", "Server 2019 · build 19041"),
            ("", "oscp.exam"),
            ("warn", "SMB signing off"),
            ("warn", "SeImpersonate"),
            ("ok", "MS01 SYSTEM"),
            ("warn", "MS02 / DC01 pending"),
        ],
        "meta": [
            ("Domain", "oscp.exam"),
            ("MS01", "192.168.118.147"),
            ("MS01 int.", "10.10.118.147"),
            ("DC01", "10.10.118.146"),
            ("Attacker", "192.168.45.158"),
            ("Result", "MS01 SYSTEM"),
        ],
        "flags": [],
        "chain": [
            ("01", "Recon", "one routable host", "#ch-01"),
            ("02", "WinRM", "<code>OSCP\\eric.wallows</code>", "#ch-02"),
            ("03", "Potato", "<code>SeImpersonate</code> → SYSTEM", "#ch-03"),
            ("04", "LSASS", "no domain-tier material", "#ch-04"),
            ("05", "Pivot", "chisel <code>R:socks</code> → <code>10.10.118.0/24</code>", "#ch-05"),
            ("06", "MS02", "the second hop", "#ch-06"),
            ("07", "DC01", "<code>proof.txt</code>", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "One routable host, two networks",
             AD / "01-reconnaissance.md"),
            ("ch-02", "02", "Foothold", "WinRM as eric.wallows", AD / "02-foothold.md"),
            ("ch-03", "03", "Privilege escalation", "SeImpersonate → SYSTEM with PrintSpoofer",
             AD / "03-privilege-escalation.md"),
            ("ch-04", "04", "Credentials", "What LSASS would and would not give",
             AD / "04-credentials.md"),
            ("ch-05", "05", "Pivot", "chisel into 10.10.118.0/24", AD / "05-pivot.md"),
            ("ch-06", "06", "MS02", "The second hop", AD / "06-ms02.md"),
            ("ch-07", "07", "DC01", "Domain admin and the flag", AD / "07-dc01.md"),
        ] + REFERENCE,
    },
    {
        "slug": "gust",
        "out": GUST / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-gust",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "FreeSWITCH 1.10.1 event socket on the default password ClueCon → command "
                       "execution as a service account → SeImpersonatePrivilege → GodPotato → SYSTEM.",
            "tags": ["Windows 10", "FreeSWITCH", "ESL", "GodPotato"],
            "foot": "local.txt + proof.txt",
        },
        "dir": GUST,
        "dir_rel": "labs/192.168.137.151-gust",
        "ip": "192.168.137.151",
        "name": "gust",
        "title": "192.168.137.151 — gust · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: FreeSWITCH 1.10.1 command "
                "execution over the event socket with the default password ClueCon, then "
                "SeImpersonatePrivilege to SYSTEM with GodPotato. Full commands, reasoning and raw output.",
        "ogdesc": "ESL 8021 + default ClueCon password → command execution as oscp\\chris → "
                  "SeImpersonatePrivilege → GodPotato → NT AUTHORITY\\SYSTEM.",
        "lede": "A Windows PBX that firewalls everything except its own management interface — and "
                "left that interface on the password it shipped with. The command execution it hands "
                "over belongs to a service account holding SeImpersonatePrivilege, which is the whole "
                "privesc.",
        "badges": [
            ("", "Windows 10 21H2"),
            ("", "build 19043.2130"),
            ("warn", "FreeSWITCH 1.10.1"),
            ("warn", "ESL 8021 · ClueCon"),
            ("warn", "SeImpersonatePrivilege"),
            ("ok", "SYSTEM · 2 flags"),
        ],
        "meta": [
            ("Host", "OSCP"),
            ("IP", "192.168.137.151"),
            ("OS", "Windows 10 21H2"),
            ("Open", "80, 3389, 5060/5080, 8021"),
            ("Product", "FreeSWITCH 1.10.1"),
            ("Result", "NT AUTHORITY\\SYSTEM"),
        ],
        "flags": [
            ("local.txt · as oscp\\chris", "9d05eefc0447258ceab32e91e3b54aac"),
            ("proof.txt · as SYSTEM", "46586fc8f483adc13d76335768bf0a4c"),
        ],
        "chain": [
            ("01", "8021", "<code>mod_event_socket</code>", "#ch-01"),
            ("02", "ClueCon", "default ESL password → <code>api system</code>", "#ch-02"),
            ("03", "chris", "command execution, then <code>nc64</code> shell", "#ch-03"),
            ("04", "Token", "High IL + <code>SeImpersonatePrivilege</code>", "#ch-04"),
            ("05", "GodPotato", "SYSTEM token → <code>cmd.exe</code> as SYSTEM", "#ch-05"),
            ("06", "proof.txt", "both flags", "#ch-06"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Thirteen ports, one product",
             GUST / "01-reconnaissance.md"),
            ("ch-02", "02", "The event socket", "Default password on a control interface",
             GUST / "02-esl.md"),
            ("ch-03", "03", "Foothold", "Command execution as chris", GUST / "03-foothold.md"),
            ("ch-04", "04", "Enumeration", "One whoami /all decides the box",
             GUST / "04-enumeration.md"),
            ("ch-05", "05", "Privilege escalation", "GodPotato, and four ways it failed first",
             GUST / "05-privilege-escalation.md"),
            ("ch-06", "06", "Flags", "Both proofs, with the account that read them",
             GUST / "06-flags.md"),
            ("ch-07", "07", "Cleanup and lessons", "Artefacts, remediation, takeaways",
             GUST / "07-cleanup-and-lessons.md"),
        ] + REFERENCE,
    },
    {
        "slug": "snmp-mouse",
        "out": WINSNMP / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-snmp-mouse",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "UDP/161 SNMP inventory → WiFi Mouse Server 1.7.8.5 RCE (CVE-2022-3218) "
                       "→ PrintNightmare → local admin → proof.txt.",
            "tags": ["Windows 10 2004", "SNMP", "Mouse Server", "PrintNightmare"],
            "foot": "offsec → adm1n · proof.txt",
        },
        "dir": WINSNMP,
        "dir_rel": "labs/192.168.103.145-snmp-mouse",
        "ip": "192.168.103.145",
        "name": "snmp-mouse",
        "title": "192.168.103.145 — snmp-mouse · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: a fully filtered TCP scan that hid "
                "an SNMP-exposed Windows host, a WiFi Mouse Server 1.7.8.5 RCE (CVE-2022-3218), and "
                "PrintNightmare for the escalation. Full commands, reasoning and raw output.",
        "ogdesc": "UDP/161 SNMP inventory → Mouse Server 1.7.8.5 RCE → PrintNightmare → local admin.",
        "lede": "Every TCP port came back filtered and the box looked dead. It was answering SNMP the "
                "whole time — and the inventory it handed over named both the vulnerable package and "
                "the precondition that makes a keystroke exploit work: somebody was logged in.",
        "badges": [
            ("", "Windows 10 · 19041"),
            ("", "windows/shell/reverse_tcp"),
            ("warn", "udp/161 public"),
            ("warn", "Mouse Server 1.7.8.5"),
            ("warn", "unpatched spooler"),
            ("ok", "local admin · proof.txt"),
        ],
        "meta": [
            ("Host", "zachary (sysName) / OSCP"),
            ("IP", "192.168.103.145"),
            ("OS", "Windows 10 2004 · build 19041"),
            ("TCP", "1978, 3389 (filtered at first scan)"),
            ("UDP", "161"),
            ("Result", "local admin adm1n"),
        ],
        "flags": [],
        "chain": [
            ("01", "Filtered", "all 10 TCP ports <code>filtered</code>", "#ch-01"),
            ("02", "UDP 161", "community <code>public</code> → inventory", "#ch-02"),
            ("03", "Analysis", "Mouse Server 1.7.8.5 + live desktop", "#ch-03"),
            ("04", "Foothold", "CVE-2022-3218 → <code>OSCP\\offsec</code>", "#ch-04"),
            ("05", "1346", "no <code>SeImpersonate</code> — potatoes are out", "#ch-05"),
            ("06", "PrintNightmare", "<code>Invoke-Nightmare</code> → <code>adm1n</code>", "#ch-06"),
            ("07", "proof.txt", "RDP as admin, then cleanup", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Ten filtered ports and a host that was alive",
             WINSNMP / "01-reconnaissance.md"),
            ("ch-02", "02", "SNMP enumeration", "Processes, software, and the 8072 dead end",
             WINSNMP / "02-snmp-enumeration.md"),
            ("ch-03", "03", "Vulnerability analysis", "CVE-2022-3218 and its real precondition",
             WINSNMP / "03-vulnerability-analysis.md"),
            ("ch-04", "04", "Foothold", "wifi_mouse_rce → shell as offsec",
             WINSNMP / "04-foothold.md"),
            ("ch-05", "05", "Enumeration &amp; dead ends", "getsystem 1346, and why potatoes fail",
             WINSNMP / "05-enumeration.md"),
            ("ch-06", "06", "Privilege escalation", "PrintNightmare from a standard user",
             WINSNMP / "06-privilege-escalation.md"),
            ("ch-07", "07", "Flags &amp; cleanup", "Proof, removing adm1n, lessons",
             WINSNMP / "07-flags-and-cleanup.md"),
        ] + REFERENCE,
    },
    {
        "slug": "git-exposure",
        "out": GITEXP / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-git-exposure",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "Served <code>.git</code> → two passwords recovered from commit history → "
                       "credential reuse onto a system account → CVE-2023-0386 overlayfs copy-up.",
            "tags": ["Ubuntu 22.04", "Git exposure", "vsftpd", "overlayfs"],
            "foot": "local.txt + proof.txt",
        },
        "dir": GITEXP,
        "dir_rel": "labs/192.168.161.144-git-exposure",
        "ip": "192.168.161.144",
        "name": "git-exposure",
        "title": "192.168.161.144 — git-exposure · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: an exposed .git directory leaks "
                "credentials through commit history, the FTP account is chrooted to /, and a GA "
                "5.15.0-53 kernel falls to CVE-2023-0386 after porting the PoC to FUSE3. "
                "Full commands, reasoning and raw output.",
        "ogdesc": "Exposed .git → git history → stuart:BreakingBad92 → FTP chroot=/ → "
                  "PwnKit refuted, GameOver(lay) refuted, CVE-2023-0386 → root.",
        "lede": "A host with no application deployed at all — every PHP file in the repository "
                "returns 404 — and whose entire entry point was a .git directory left readable by "
                "Apache. The commit called Security Update is the one that says credentials were "
                "there; its parent still has them. Two of the three obvious kernel escalations are "
                "dead, and the third only works after the public exploit is ported to a library "
                "the target actually ships.",
        "badges": [
            ("", "Ubuntu 22.04.1"),
            ("", "vsftpd 3.0.5"),
            ("", "OpenSSH 8.9p1"),
            ("", "Apache 2.4.52"),
            ("warn", ".git exposed"),
            ("ok", "root · 2 flags"),
        ],
        "meta": [
            ("Host", "lab-pwk2-…-ubuntu2204"),
            ("IP", "192.168.161.144"),
            ("OS", "Ubuntu 22.04.1 · 5.15.0-53"),
            ("TCP", "21, 22, 80"),
            ("Entry", ".git → history"),
            ("Result", "root"),
        ],
        "flags": [
            ("local.txt · as stuart", "bb8e8b0b546a972d8280c494463cbf93"),
            ("proof.txt · as root", "fffa8aa85fea084e31de521432d8e8b9"),
        ],
        "chain": [
            ("01", "Recon", "21 / 22 / 80 — and gopher <code>:70</code> closed", "#ch-01"),
            ("02", ".git", "<code>/.git/config</code> → remote URL + token", "#ch-02"),
            ("03", "History", "<code>git show 44a055d^</code> → the password", "#ch-03"),
            ("04", "Foothold", "reuse → <code>ssh stuart</code>, FTP <code>pwd=/</code>", "#ch-04"),
            ("05", "Enumerate", "no sudo, no caps, <code>5.15.0-53</code>", "#ch-05"),
            ("06", "Escalate", "2 refuted → CVE-2023-0386 via FUSE3", "#ch-06"),
            ("07", "proof.txt", "root, then cleanup", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Three services, and a dead end closed with evidence",
             GITEXP / "01-reconnaissance.md"),
            ("ch-02", "02", "Web enumeration", "Why /.git/ answers 301 — and why it is the whole box",
             GITEXP / "02-web-enumeration.md"),
            ("ch-03", "03", "Dumping the repository", "git-dumper, and reading history as an archive",
             GITEXP / "03-git-dump.md"),
            ("ch-04", "04", "Foothold", "Credential reuse, and a chroot that is the whole filesystem",
             GITEXP / "04-foothold.md"),
            ("ch-05", "05", "Enumeration", "Nothing in sudo, SUID or cron — the kernel is the finding",
             GITEXP / "05-enumeration.md"),
            ("ch-06", "06", "Privilege escalation", "PwnKit refuted, GameOver(lay) refuted, overlayfs lands",
             GITEXP / "06-privilege-escalation.md"),
            ("ch-07", "07", "Flags &amp; cleanup", "Proof, removing the SUID shell, lessons",
             GITEXP / "07-flags-and-cleanup.md"),
        ] + REFERENCE,
    },
    {
        "slug": "aerospike-screen",
        "out": AERO / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "Unauthenticated Aerospike 5.1.0.1 UDF → <code>aero</code> shell → "
                       "setuid screen 4.5.0 → root.",
            "tags": ["Ubuntu 20.04", "Aerospike", "SUID", "Lua"],
            "foot": "local.txt + proof.txt",
        },
        "dir": AERO,
        "dir_rel": "labs/192.168.150.143-aerospike-screen",
        "ip": "192.168.150.143",
        "name": "aerospike-screen",
        "title": "192.168.150.143 — aerospike-screen · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: an unauthenticated Aerospike "
                "database that runs uploaded Lua, then a setuid screen 4.5.0 to root. Full "
                "commands, reasoning and raw output.",
        "ogdesc": "Aerospike 5.1.0.1 UDF → aero shell → setuid screen 4.5.0 → root.",
        "lede": "Ten open ports, four of them unnamed, and the one that mattered was a database "
                "nobody had ever authenticated. Behind it, a setuid binary from 2017 that the "
                "package database insisted was patched.",
        "badges": [
            ("", "Ubuntu 20.04.4"),
            ("", "Aerospike 5.1.0.1"),
            ("", "Apache 2.4.41"),
            ("warn", "setuid screen 4.5.0"),
            ("warn", "no egress"),
            ("ok", "root · 2 flags"),
        ],
        "meta": [
            ("Host", "lab-pwk2-…-aero-242-100"),
            ("IP", "192.168.150.143"),
            ("OS", "Ubuntu 20.04.4 · 5.4.0-104"),
            ("TCP", "21, 22, 80, 81, 443, 3000, 3001, 3003, 3306, 5432"),
            ("UDP", "not scanned"),
            ("Result", "root"),
        ],
        "flags": [
            ("local.txt · as aero", "8d0b2414df3c73b491d05711c000a9d6"),
            ("proof.txt · as root", "7fd0bd2e18b52d791a6600fbd8e622b7"),
        ],
        "chain": [
            ("01", "Recon", "10 open, 65525 <em>filtered</em>", "#ch-01"),
            ("02", "Web", "Pico CMS, nginx page on <code>:81</code>", "#ch-02"),
            ("03", "Aerospike", "<code>build=5.1.0.1</code>, no auth", "#ch-03"),
            ("04", "UDF", "<code>io.popen</code> → <code>aero</code> · local.txt", "#ch-04"),
            ("05", "Enum", "PwnKit out, <code>screen-4.5.0</code> in", "#ch-05"),
            ("06", "screen", "<code>ld.so.preload</code> via <code>umask 000</code>", "#ch-06"),
            ("07", "proof.txt", "root, then cleanup", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Ten ports, and why <em>filtered</em> is not <em>closed</em>",
             AERO / "01-reconnaissance.md"),
            ("ch-02", "02", "Web enumeration", "Pico CMS under /index/, and the vhost that lies",
             AERO / "02-web-enumeration.md"),
            ("ch-03", "03", "Aerospike", "Naming the daemon, reading 5.1.0.1 off the wire",
             AERO / "03-aerospike.md"),
            ("ch-04", "04", "Foothold", "Lua that runs shell — and a host that cannot call back",
             AERO / "04-foothold.md"),
            ("ch-05", "05", "Enumeration", "Two refutations, one unreadable cron, no compiler",
             AERO / "05-enumeration.md"),
            ("ch-06", "06", "Privilege escalation", "setuid screen 4.5.0, CRLF and the rewrite",
             AERO / "06-privilege-escalation.md"),
            ("ch-07", "07", "Flags &amp; cleanup", "Proof, artefact removal, lessons",
             AERO / "07-flags-and-cleanup.md"),
        ] + REFERENCE,
    },
]

# markdown filename -> in-page anchor, plus the evidence blob prefix, per machine
for _m in LABS:
    _m["links"] = {"README.md": "#overview"}
    for _cid, _num, _title, _sub, _path in _m["chapters"]:
        _m["links"][_path.name] = "#" + _cid
    _m["evidence"] = f"{REPO}/blob/main/{_m['dir_rel']}/evidence/"


def fix_links(text: str, mach: dict) -> str:
    """Rewrite relative markdown links to anchors or GitHub blob URLs."""
    def repl(m):
        href = m.group(1)
        if href.startswith(("http://", "https://", "#", "mailto:")):
            return m.group(0)
        frag = ""
        if "#" in href:
            href, frag = href.split("#", 1)
            frag = "#" + frag
        name = pathlib.PurePosixPath(href).name
        if name in mach["links"]:
            return 'href="%s%s"' % (mach["links"][name], frag)
        if href.endswith(".txt"):
            return 'href="%s%s"' % (mach["evidence"] + name, frag)
        return 'href="%s%s"' % (REPO + "/blob/main/" + href, frag)

    return re.sub(r'href="([^"]+)"', repl, text)


CMD_LANGS = {"bash", "sh", "shell", "console", "zsh", "powershell", "ps1", "ps", "cmd", "bat", "dos"}
FENCE = re.compile(r"^```([^\n`]*)\n(.*?)^```\s*$", re.S | re.M)
FORMATTER = HtmlFormatter(nowrap=True, style="monokai")


def code_block(code: str, lang: str) -> str:
    """Render one fenced block as a command or output card."""
    code = code.strip("\n")
    is_cmd = lang.lower() in CMD_LANGS
    label = "command" if is_cmd else "output"
    cls = "block block-cmd" if is_cmd else "block block-out"

    if lang:
        try:
            lexer = get_lexer_by_name(lang, stripnl=False, ensurenl=False)
        except ClassNotFound:
            lexer = None
    else:
        lexer = None

    if lexer is not None:
        inner = highlight(code, lexer, FORMATTER)
    else:
        inner = '<span class="plain">%s</span>' % html.escape(code, quote=False)

    btn = ('<button class="copy" type="button" aria-label="Copy command">Copy</button>'
           if is_cmd else "")
    return (
        '<div class="%s" data-kind="%s">'
        '<div class="block-bar"><span class="block-tag">%s</span>%s</div>'
        '<pre>%s</pre></div>' % (cls, label, label, btn, inner)
    )


def render(path: pathlib.Path, mach: dict) -> str:
    src = path.read_text(encoding="utf-8")
    # drop the leading H1, the page supplies its own heading
    src = re.sub(r"\A\s*#\s+.*?\n", "", src, count=1)

    # demote headings one level: the chapter title is the h2, so every '##' section below it
    # becomes an h3 and is turned into a collapsible card by the client script
    src = re.sub(r"^(#{1,5})(\s)", r"#\1\2", src, flags=re.M)

    # pull fenced blocks out before markdown runs, so we keep the language info the
    # renderer would otherwise discard
    blocks = []

    def stash(m):
        blocks.append((m.group(1).strip(), m.group(2)))
        return "\n\nCODEPLACEHOLDER%sZ\n\n" % (len(blocks) - 1)

    src = FENCE.sub(stash, src)

    md = markdown.Markdown(
        extensions=["tables", "attr_list", "sane_lists"],
    )
    out = md.convert(src)
    out = fix_links(out, mach)

    def unstash(m):
        idx = int(m.group(1))
        lang, code = blocks[idx]
        return code_block(code, lang)

    return re.sub(r"<p>CODEPLACEHOLDER(\d+)Z</p>", unstash, out)


def build_body(mach: dict) -> str:
    parts = []
    for cid, num, title, sub, path in mach["chapters"]:
        body = render(path, mach)
        parts.append(
            f'<section class="chapter" id="{cid}" data-title="{re.sub(r"&amp;", "and", title)}">'
            f'<div class="ch-head">'
            f'<span class="ch-num">{num}</span>'
            f'<div class="ch-title"><h2>{title}</h2><p class="ch-sub">{sub}</p></div>'
            f'<button class="ghost copyall" type="button">Copy commands</button>'
            f"</div>"
            f'<div class="content">{body}</div>'
            f"</section>"
        )
    return "\n".join(parts)


def build_nav(mach: dict) -> str:
    items = []
    for cid, num, title, sub, _ in mach["chapters"]:
        items.append(
            f'<a class="nav-item" href="#{cid}" data-target="{cid}">'
            f'<span class="nav-num">{num}</span>'
            f'<span class="nav-label">{title}</span>'
            f'<input class="nav-check" type="checkbox" data-ch="{cid}" '
            f'aria-label="Mark {re.sub(r"&amp;", "and", title)} complete">'
            f"</a>"
        )
    return "\n".join(items)


def build_chain(mach: dict) -> str:
    out = []
    for num, label, desc, href in mach["chain"]:
        out.append(
            f'<a class="step" href="{href}">'
            f'<span class="step-num">{num}</span>'
            f'<span class="step-label">{label}</span>'
            f'<span class="step-desc">{desc}</span>'
            f"</a>"
        )
    return "\n".join(out)


CSS = r"""
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#0a0e13; --bg2:#0f151d; --panel:#0d131b; --line:#1c2836; --line2:#263545;
  --fg:#dde5ee; --dim:#8697ab; --dim2:#5d6d80;
  --acc:#3fb950; --acc-dim:#1f6f31; --amber:#d29922; --red:#f85149; --link:#58a6ff;
  --code:#070a0e; --shadow:0 20px 50px rgba(0,0,0,.45);
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
}
[data-theme="light"]{
  --bg:#f4f6f9; --bg2:#ffffff; --panel:#ffffff; --line:#e3e8ef; --line2:#d3dae4;
  --fg:#151b23; --dim:#5a6675; --dim2:#7d8898;
  --acc:#1a7f37; --acc-dim:#8fd19e; --amber:#9a6700; --red:#cf222e; --link:#0969da;
  --code:#0d1117; --shadow:0 16px 40px rgba(15,25,40,.10);
}
html{scroll-behavior:smooth}
body{
  margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);
  font-size:16px;line-height:1.62;-webkit-font-smoothing:antialiased;
}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:var(--mono);font-size:.88em}
.skip{position:absolute;left:-9999px;top:0;background:var(--acc);color:#04120a;padding:10px 16px;z-index:99}
.skip:focus{left:8px;top:8px}

/* ---------- top bar ---------- */
.topbar{
  position:sticky;top:0;z-index:40;display:flex;align-items:center;gap:14px;
  padding:10px 18px;background:color-mix(in srgb,var(--bg) 88%,transparent);
  backdrop-filter:blur(14px);border-bottom:1px solid var(--line);
}
.brand{display:flex;align-items:center;gap:9px;font-weight:700;letter-spacing:.02em;white-space:nowrap}
.brand .dot{width:9px;height:9px;border-radius:50%;background:var(--acc);box-shadow:0 0 12px var(--acc)}
.brand .slash{color:var(--dim2);font-weight:400}
.brand-sub{color:var(--dim);font-weight:500}
.search-wrap{position:relative;flex:1;max-width:460px;margin-left:auto}
#search{
  width:100%;padding:9px 13px;border-radius:10px;border:1px solid var(--line2);
  background:var(--bg2);color:var(--fg);font-family:var(--sans);font-size:14px;outline:none;
}
#search:focus{border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 18%,transparent)}
.search-count{position:absolute;right:10px;top:50%;transform:translateY(-50%);font-size:11px;color:var(--dim2)}
.icon-btn{
  background:var(--bg2);border:1px solid var(--line2);color:var(--fg);border-radius:10px;
  width:38px;height:38px;font-size:16px;cursor:pointer;line-height:1;
}
.icon-btn:hover{border-color:var(--acc)}
.burger{display:none;background:none;border:1px solid var(--line2);color:var(--fg);border-radius:9px;width:38px;height:38px;font-size:17px;cursor:pointer}

/* ---------- shell ---------- */
.shell{display:grid;grid-template-columns:296px minmax(0,1fr);gap:0;align-items:start}
.sidebar{
  position:sticky;top:59px;height:calc(100vh - 59px);overflow-y:auto;padding:20px 16px 60px;
  border-right:1px solid var(--line);background:var(--bg);
}
.sidebar::-webkit-scrollbar{width:9px}
.sidebar::-webkit-scrollbar-thumb{background:var(--line2);border-radius:9px}

.card{border:1px solid var(--line);border-radius:14px;padding:14px;background:var(--panel);margin-bottom:16px}
.card h3{margin:0 0 10px;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}
.progress-track{height:6px;border-radius:99px;background:var(--line);overflow:hidden}
.progress-fill{height:100%;width:0;background:linear-gradient(90deg,var(--acc-dim),var(--acc));transition:width .35s ease}
.progress-label{margin-top:9px;font-size:12px;color:var(--dim);display:flex;justify-content:space-between}
.progress-label b{color:var(--fg)}

.nav-title{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim2);margin:4px 8px 8px}
.nav-item{
  display:grid;grid-template-columns:26px 1fr 20px;align-items:center;gap:8px;
  padding:9px 10px;border-radius:10px;color:var(--fg);font-size:14px;
  border:1px solid transparent;text-decoration:none;
}
.nav-item:hover{background:var(--bg2);text-decoration:none}
.nav-item.active{background:color-mix(in srgb,var(--acc) 12%,transparent);border-color:color-mix(in srgb,var(--acc) 35%,transparent)}
.nav-item.active .nav-num{color:var(--acc)}
.nav-item.done .nav-label{color:var(--dim);text-decoration:line-through}
.nav-num{font-family:var(--mono);font-size:11px;color:var(--dim2)}
.nav-check{appearance:none;width:16px;height:16px;border:1.5px solid var(--line2);border-radius:5px;cursor:pointer;margin:0;background:transparent}
.nav-check:checked{background:var(--acc);border-color:var(--acc)}
.nav-check:checked::after{content:"✓";display:block;color:#04120a;font-size:12px;line-height:13px;text-align:center;font-weight:700}
.nav-tools{display:flex;gap:8px;margin-top:12px}
.ghost{
  flex:1;background:var(--bg2);border:1px solid var(--line2);color:var(--dim);
  padding:7px 10px;border-radius:9px;font-size:12px;cursor:pointer;font-family:var(--sans);
}
.ghost:hover{color:var(--fg);border-color:var(--acc)}
.meta-line{display:flex;justify-content:space-between;gap:10px;font-size:12px;padding:5px 0;border-bottom:1px dashed var(--line)}
.meta-line:last-child{border-bottom:0}
.meta-line span:first-child{color:var(--dim)}
.meta-line span:last-child{font-family:var(--mono);font-size:11px;text-align:right}

/* ---------- main ---------- */
main{padding:34px 36px 90px;max-width:1000px;width:100%}

.hero{margin-bottom:38px}
.eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--acc);margin-bottom:12px}
.hero h1{margin:0;font-size:clamp(28px,4vw,44px);line-height:1.12;letter-spacing:-.025em;font-family:var(--sans)}
.hero h1 .ip{font-family:var(--mono);font-weight:600;font-size:.9em;letter-spacing:-.045em}
.hero h1 .name{color:var(--dim);font-weight:500}
.lede{color:var(--dim);font-size:17px;max-width:68ch;margin:14px 0 18px}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:22px}
.badge{
  font-size:12px;padding:5px 11px;border-radius:99px;border:1px solid var(--line2);
  color:var(--dim);background:var(--bg2);font-family:var(--mono);
}
.badge.ok{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 40%,transparent);background:color-mix(in srgb,var(--acc) 9%,transparent)}
.badge.warn{color:var(--amber);border-color:color-mix(in srgb,var(--amber) 40%,transparent);background:color-mix(in srgb,var(--amber) 9%,transparent)}

.chain{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:8px 0 6px}
.step{
  position:relative;display:flex;flex-direction:column;gap:3px;padding:12px;border-radius:12px;
  border:1px solid var(--line);background:var(--panel);color:var(--fg);text-decoration:none;
  transition:transform .15s ease,border-color .15s ease;
}
.step:hover{transform:translateY(-2px);border-color:var(--acc);text-decoration:none}
.step-num{font-family:var(--mono);font-size:10px;color:var(--acc)}
.step-label{font-weight:650;font-size:14px}
.step-desc{font-size:11.5px;color:var(--dim);line-height:1.45}
.step-desc code{font-size:11px;background:var(--code);padding:1px 4px;border-radius:4px;color:#c9d5e4}

.flags{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:26px 0 10px}
.flag{border:1px solid var(--line);border-radius:14px;padding:16px;background:var(--panel)}
.flag .k{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim2);margin-bottom:8px}
.flag .v{font-family:var(--mono);font-size:14px;word-break:break-all;min-height:22px}
.flag.revealed .v{color:var(--acc)}
.flag .reveal{margin-top:10px;background:none;border:0;color:var(--link);font-size:12px;cursor:pointer;padding:0}
.flag .masked{letter-spacing:.18em;color:var(--dim2)}

/* ---------- chapters ---------- */
.chapter{scroll-margin-top:78px;margin:0 0 34px;border-top:1px solid var(--line);padding-top:26px}
.ch-head{display:flex;align-items:flex-start;gap:14px;margin-bottom:6px}
.ch-num{
  font-family:var(--mono);font-size:12px;color:var(--acc);border:1px solid color-mix(in srgb,var(--acc) 35%,transparent);
  background:color-mix(in srgb,var(--acc) 9%,transparent);border-radius:9px;padding:6px 9px;flex:none;
}
.ch-title{flex:1;min-width:0}
.ch-title h2{margin:0;font-size:24px;letter-spacing:-.01em}
.ch-sub{margin:2px 0 0;color:var(--dim);font-size:13.5px}
.copyall{flex:none;max-width:140px}

.content{font-size:15.3px}
.content h3{font-size:18px;margin:0;letter-spacing:-.01em}
.content h4{font-size:14px;margin:22px 0 8px;color:var(--dim);letter-spacing:.04em;text-transform:uppercase}
.content p{margin:10px 0}
.content ul,.content ol{padding-left:22px;margin:10px 0}
.content li{margin:5px 0}
.content strong{color:#fff}
[data-theme="light"] .content strong{color:#000}
.content code{
  background:color-mix(in srgb,var(--line2) 42%,transparent);border:1px solid var(--line);
  padding:.1em .36em;border-radius:5px;color:#e8eff8;white-space:nowrap;
}
[data-theme="light"] .content code{color:#0d1520;background:#edf1f6}
.block pre code,.block pre span{background:none;border:0;padding:0}
.content td code,.content li code{white-space:normal}
.content hr{border:0;border-top:1px solid var(--line);margin:26px 0}
.content blockquote{margin:14px 0;padding:10px 14px;border-left:3px solid var(--amber);background:color-mix(in srgb,var(--amber) 7%,transparent);border-radius:0 8px 8px 0;color:var(--dim)}
.content blockquote p{margin:4px 0}

.sec{border:1px solid var(--line);border-radius:12px;margin:14px 0;background:color-mix(in srgb,var(--panel) 60%,transparent);overflow:hidden}
.sec-head{
  width:100%;display:flex;align-items:center;gap:10px;background:none;border:0;color:var(--fg);
  padding:12px 15px;font-size:17px;font-weight:650;cursor:pointer;text-align:left;font-family:var(--sans);
}
.sec-head:hover{background:var(--bg2)}
.sec-head::before{content:"";flex:none;width:7px;height:7px;margin-top:-3px;border-right:1.7px solid var(--dim2);border-bottom:1.7px solid var(--dim2);transform:rotate(-45deg);transition:transform .18s ease}
.sec-head[aria-expanded="true"]::before{transform:rotate(45deg);margin-top:-5px}
.sec-body{padding:2px 15px 14px}
.sec-body[hidden]{display:none}

/* tables */
table{border-collapse:collapse;width:100%;margin:14px 0;font-size:13.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:8px 11px;text-align:left;vertical-align:top}
th{background:var(--bg2);font-weight:600;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--dim)}
tr:nth-child(even) td{background:color-mix(in srgb,var(--bg2) 55%,transparent)}

/* code cards */
.block{margin:12px 0;border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--code)}
.block-bar{
  display:flex;align-items:center;justify-content:space-between;padding:6px 10px;
  background:#0b1017;border-bottom:1px solid #16202c;
}
[data-theme="light"] .block-bar{background:#161b22;border-bottom-color:#232c38}
.block-tag{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#5f7085}
.block-cmd .block-tag{color:#3fb950}
.copy{
  background:#131c26;border:1px solid #24313f;color:#9fb0c3;border-radius:7px;
  font-size:11px;padding:3px 9px;cursor:pointer;font-family:var(--sans);
}
.copy:hover{color:#fff;border-color:#3fb950}
.copy.done{color:#3fb950;border-color:#3fb950}
.block pre{margin:0;padding:13px 15px;overflow-x:auto;font-family:var(--mono);font-size:12.9px;line-height:1.6;color:#c9d5e4}
.block-out{border-style:dashed}
.block-out pre{color:#93a3b6}
.codehilite{background:transparent}
.codehilite pre{margin:0}
.highlight .c,.highlight .c1,.highlight .cm{color:#5f7085;font-style:italic}
.highlight .k,.highlight .kn,.highlight .kd{color:#d2a8ff}
.highlight .s,.highlight .s1,.highlight .s2,.highlight .sb{color:#7ee787}
.highlight .nb,.highlight .nf{color:#79c0ff}
.highlight .nv,.highlight .vi{color:#ffa657}
.highlight .mi,.highlight .m{color:#ffa657}
.highlight .o,.highlight .p{color:#c9d5e4}
.highlight .gp{color:#3fb950;font-weight:700}

footer{margin-top:50px;padding-top:22px;border-top:1px solid var(--line);color:var(--dim2);font-size:12.5px;display:flex;flex-wrap:wrap;gap:14px;justify-content:space-between}

/* toast + top button */
#toast{
  position:fixed;left:50%;bottom:26px;transform:translate(-50%,20px);opacity:0;pointer-events:none;
  background:var(--acc);color:#04120a;padding:9px 16px;border-radius:99px;font-size:13px;font-weight:650;
  transition:opacity .2s ease,transform .2s ease;z-index:60;
}
#toast.show{opacity:1;transform:translate(-50%,0)}
#toTop{
  position:fixed;right:22px;bottom:22px;width:42px;height:42px;border-radius:50%;
  background:var(--panel);border:1px solid var(--line2);color:var(--fg);cursor:pointer;
  opacity:0;pointer-events:none;transition:opacity .2s ease;z-index:50;font-size:16px;
}
#toTop.show{opacity:1;pointer-events:auto}
#toTop:hover{border-color:var(--acc)}

mark.hit{background:color-mix(in srgb,var(--amber) 45%,transparent);color:inherit;border-radius:3px}

@media (max-width:940px){
  .shell{grid-template-columns:1fr}
  .sidebar{
    position:fixed;inset:59px 0 0 0;height:auto;z-index:35;transform:translateX(-102%);
    transition:transform .22s ease;width:296px;box-shadow:var(--shadow);
  }
  .sidebar.open{transform:none}
  .burger{display:block}
  main{padding:24px 18px 80px}
  .search-wrap{max-width:none}
  .copyall{display:none}
  .brand-sub,.brand .slash{display:none}
}
@media print{
  .topbar,.sidebar,#toTop,#toast,.copy,.copyall,.block-bar{display:none!important}
  .shell{display:block}
  main{padding:0;max-width:none}
  body{background:#fff;color:#000}
  .sec{border:0;margin:0}
  .sec-head{font-size:14px}
  .sec-body{display:block!important}
}
"""

JS = r"""
(function(){
  "use strict";
  var root=document.documentElement;

  /* ---------- theme ---------- */
  var THEME_KEY="oscp-theme";
  function setTheme(t){root.setAttribute("data-theme",t);try{localStorage.setItem(THEME_KEY,t)}catch(e){}}
  var saved=null;try{saved=localStorage.getItem(THEME_KEY)}catch(e){}
  if(!saved){saved=window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}
  setTheme(saved);
  document.getElementById("themeBtn").addEventListener("click",function(){
    setTheme(root.getAttribute("data-theme")==="dark"?"light":"dark");
  });

  /* ---------- wrap h3 sections into collapsible cards ---------- */
  document.querySelectorAll(".content").forEach(function(content){
    var kids=Array.prototype.slice.call(content.children);
    var current=null, sec=null, body=null;
    kids.forEach(function(el){
      if(el.tagName==="H3"){
        sec=document.createElement("section");sec.className="sec";
        var btn=document.createElement("button");
        btn.type="button";btn.className="sec-head";btn.setAttribute("aria-expanded","true");
        btn.textContent=el.textContent;
        body=document.createElement("div");body.className="sec-body";
        content.insertBefore(sec,el);
        sec.appendChild(btn);sec.appendChild(body);
        el.remove();
        btn.addEventListener("click",function(){
          var panel=btn.nextElementSibling;
          var open=btn.getAttribute("aria-expanded")==="true";
          btn.setAttribute("aria-expanded",open?"false":"true");
          if(panel)panel.hidden=open;
        });
        current=body;
      }else if(current){
        current.appendChild(el);
      }
    });
  });

  /* ---------- copy buttons ---------- */
  var toast=document.getElementById("toast"),toastTimer=null;
  function say(msg){
    toast.textContent=msg;toast.classList.add("show");
    clearTimeout(toastTimer);toastTimer=setTimeout(function(){toast.classList.remove("show")},1600);
  }
  function copy(text,btn){
    function ok(){if(btn){btn.classList.add("done");var t=btn.textContent;btn.textContent="Copied";
      setTimeout(function(){btn.classList.remove("done");btn.textContent=t},1400);}say("Copied to clipboard");}
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(ok).catch(function(){fallback(text);ok();});
    }else{fallback(text);ok();}
  }
  function fallback(text){
    var ta=document.createElement("textarea");ta.value=text;ta.style.position="fixed";ta.style.opacity="0";
    document.body.appendChild(ta);ta.select();try{document.execCommand("copy")}catch(e){}document.body.removeChild(ta);
  }
  document.addEventListener("click",function(e){
    var btn=e.target.closest(".copy");
    if(!btn)return;
    var block=btn.closest(".block"),pre=block&&block.querySelector("pre");
    if(pre)copy(pre.innerText.replace(/\s+$/,""),btn);
  });

  /* copy every command in a chapter */
  document.querySelectorAll(".copyall").forEach(function(btn){
    btn.addEventListener("click",function(){
      var ch=btn.closest(".chapter");
      var cmds=Array.prototype.map.call(ch.querySelectorAll(".block-cmd pre"),function(p){return p.innerText.replace(/\s+$/,"")});
      if(!cmds.length){say("No commands in this chapter");return;}
      copy(cmds.join("\n\n"),btn);
    });
  });

  /* ---------- progress ---------- */
  var PKEY="%%PKEY%%";
  var checks=Array.prototype.slice.call(document.querySelectorAll(".nav-check"));
  var done={};try{done=JSON.parse(localStorage.getItem(PKEY)||"{}")}catch(e){}
  function paint(){
    var n=0;
    checks.forEach(function(c){
      var on=!!done[c.dataset.ch];
      c.checked=on;
      c.closest(".nav-item").classList.toggle("done",on);
      if(on)n++;
    });
    var pct=Math.round(n/checks.length*100);
    document.getElementById("bar").style.width=pct+"%";
    document.getElementById("pcount").textContent=n+" / "+checks.length;
    document.getElementById("ppct").textContent=pct+"%";
  }
  checks.forEach(function(c){
    c.addEventListener("click",function(e){e.stopPropagation()});
    c.addEventListener("change",function(){
      done[c.dataset.ch]=c.checked;
      try{localStorage.setItem(PKEY,JSON.stringify(done))}catch(e){}
      paint();
    });
  });
  paint();
  document.getElementById("resetProgress").addEventListener("click",function(){
    done={};try{localStorage.setItem(PKEY,"{}")}catch(e){}paint();say("Progress reset");
  });

  /* ---------- expand / collapse all ---------- */
  function setAll(open){
    document.querySelectorAll(".sec-head").forEach(function(b){
      b.setAttribute("aria-expanded",open?"true":"false");
      b.nextElementSibling.hidden=!open;
    });
  }
  document.getElementById("expandAll").addEventListener("click",function(){setAll(true)});
  document.getElementById("collapseAll").addEventListener("click",function(){setAll(false)});

  /* ---------- scroll spy ---------- */
  var navItems=Array.prototype.slice.call(document.querySelectorAll(".nav-item"));
  var chapters=Array.prototype.slice.call(document.querySelectorAll(".chapter"));
  if("IntersectionObserver" in window){
    var io=new IntersectionObserver(function(entries){
      entries.forEach(function(en){
        if(!en.isIntersecting)return;
        navItems.forEach(function(n){n.classList.toggle("active",n.dataset.target===en.target.id)});
      });
    },{rootMargin:"-70px 0px -70% 0px",threshold:0});
    chapters.forEach(function(c){io.observe(c)});
  }

  /* ---------- search ---------- */
  var input=document.getElementById("search"),count=document.getElementById("searchCount");
  var index=chapters.map(function(c){
    return {el:c,item:document.querySelector('.nav-item[data-target="'+c.id+'"]'),
            text:(c.dataset.title+" "+c.textContent).toLowerCase()};
  });
  function clearMarks(){
    document.querySelectorAll("mark.hit").forEach(function(m){
      var p=m.parentNode;m.replaceWith(document.createTextNode(m.textContent));p.normalize();
    });
  }
  function run(){
    var q=input.value.trim().toLowerCase();
    clearMarks();
    if(!q){
      index.forEach(function(r){r.item.style.display="";r.el.style.display=""});
      count.textContent="";return;
    }
    var hits=0,first=null;
    index.forEach(function(r){
      var hit=r.text.indexOf(q)!==-1;
      r.item.style.display=hit?"":"none";
      r.el.style.display=hit?"":"none";
      if(hit){hits++;if(!first)first=r;}
    });
    count.textContent=hits?hits+" chapter"+(hits>1?"s":""):"no match";
    if(first&&hits===1){first.el.scrollIntoView({block:"start"});}
  }
  var t=null;
  input.addEventListener("input",function(){clearTimeout(t);t=setTimeout(run,140)});
  input.addEventListener("keydown",function(e){
    if(e.key==="Escape"){input.value="";run();input.blur();}
    if(e.key==="Enter"){var vis=index.filter(function(r){return r.item.style.display!=="none"});if(vis.length){vis[0].el.scrollIntoView({block:"start"})}}
  });

  /* ---------- keyboard ---------- */
  document.addEventListener("keydown",function(e){
    var typing=/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if(e.key==="/"&&!typing){e.preventDefault();input.focus();input.select();}
  });

  /* ---------- mobile sidebar ---------- */
  var sidebar=document.getElementById("sidebar");
  document.getElementById("burger").addEventListener("click",function(){sidebar.classList.toggle("open")});
  navItems.forEach(function(n){n.addEventListener("click",function(){sidebar.classList.remove("open")})});

  /* ---------- flag reveal ---------- */
  document.querySelectorAll(".flag .reveal").forEach(function(b){
    b.addEventListener("click",function(){
      var flag=b.closest(".flag"),v=flag.querySelector(".v");
      var val=v.dataset.value;
      var on=flag.classList.toggle("revealed");
      v.innerHTML=on?'<span>'+val+'</span>':'<span class="masked">••••••••••••••••••••••••••••••••</span>';
      b.textContent=on?"hide":"reveal";
    });
  });

  /* ---------- back to top ---------- */
  var topBtn=document.getElementById("toTop");
  window.addEventListener("scroll",function(){
    topBtn.classList.toggle("show",window.scrollY>600);
  },{passive:true});
  topBtn.addEventListener("click",function(){window.scrollTo({top:0,behavior:"smooth"})});

  /* ---------- deep links ---------- */
  if(location.hash){
    var target=document.querySelector(location.hash);
    if(target)setTimeout(function(){target.scrollIntoView({block:"start"})},60);
  }
})();
"""

TEMPLATE = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%%TITLE%%</title>
<meta name="description" content="%%DESC%%">
<meta property="og:type" content="article">
<meta property="og:title" content="%%TITLE%%">
<meta property="og:description" content="%%OGDESC%%">
<meta name="color-scheme" content="dark light">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>💀</text></svg>">
<style>%%CSS%%</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>

<header class="topbar">
  <button class="burger" id="burger" type="button" aria-label="Open navigation">☰</button>
  <div class="brand"><span class="dot"></span>OSCP<span class="slash">/</span><span class="brand-sub">%%NAME%%</span></div>
  <div class="search-wrap">
    <input id="search" type="search" placeholder="Search chapters…   ( / )" autocomplete="off" aria-label="Search chapters">
    <span class="search-count" id="searchCount"></span>
  </div>
  <button class="icon-btn" id="themeBtn" type="button" aria-label="Toggle colour theme" title="Toggle theme">◐</button>
</header>

<div class="shell">
  <aside class="sidebar" id="sidebar">
    <div class="card">
      <h3>Progress</h3>
      <div class="progress-track"><div class="progress-fill" id="bar"></div></div>
      <div class="progress-label"><span><b id="pcount">0 / %%CHN%%</b> chapters</span><span id="ppct">0%</span></div>
    </div>

    <div class="nav-title">Chapters</div>
    <nav>%%NAV%%</nav>
    <div class="nav-tools">
      <button class="ghost" id="expandAll" type="button">Expand all</button>
      <button class="ghost" id="collapseAll" type="button">Collapse all</button>
    </div>
    <div class="nav-tools"><button class="ghost" id="resetProgress" type="button">Reset progress</button></div>

    <div class="card" style="margin-top:16px">
      <h3>Target</h3>
%%METAROWS%%
    </div>

    <div class="card">
      <h3>Source</h3>
      <div class="meta-line"><span>Repo</span><span><a href="%%REPO%%">AV10V/OSCP</a></span></div>
      <div class="meta-line"><span>Notes</span><span>markdown</span></div>
      <div class="meta-line"><span>All labs</span><span><a href="%%HOME%%">main</a></span></div>
    </div>
  </aside>

  <main id="main">
    <section class="hero" id="overview">
      <div class="eyebrow">OSCP lab walkthrough</div>
      <h1><span class="ip">%%IP%%</span> <span class="name">— %%NAME%%</span></h1>
      <p class="lede">
        %%LEDE%%
      </p>
      <div class="badges">
%%BADGES%%
      </div>
      <div class="chain">%%CHAIN%%</div>
      <div class="flags">
%%FLAGS%%
      </div>
    </section>

    %%BODY%%

    <footer>
      <span>Authorised lab environment · flags and credentials are lab-specific</span>
      <span><a href="%%REPO%%">source on GitHub</a> · built %%DATE%%</span>
    </footer>
  </main>
</div>

<button id="toTop" type="button" aria-label="Back to top">↑</button>
<div id="toast" role="status" aria-live="polite"></div>
<script>%%JS%%</script>
</body>
</html>
"""


HOME_CSS = r"""
/* ---------- landing page ---------- */
body.home-body{
  background:
    radial-gradient(1100px 520px at 18% -12%, color-mix(in srgb,var(--acc) 10%,transparent), transparent 62%),
    var(--bg);
}
main.home{max-width:1140px;margin:0 auto;padding:48px 24px 80px}
.home-hero{padding:14px 0 8px}
.home-hero .eyebrow{margin-bottom:14px}
.home-hero h1{font-size:clamp(32px,5.2vw,58px);line-height:1.04;letter-spacing:-.035em;margin:0 0 16px}
.home-hero h1 .dim{color:var(--dim2)}
.home-hero .lede{font-size:17.5px;max-width:64ch;margin:0 0 26px}
.picker{
  border:1px solid var(--line);background:color-mix(in srgb,var(--panel) 88%,transparent);
  border-radius:18px;padding:18px;max-width:700px;box-shadow:var(--shadow);
}
.picker label{display:block;font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim2);margin-bottom:9px}
.picker-row{display:flex;gap:10px;flex-wrap:wrap}
#labSelect{
  flex:1 1 320px;min-width:0;appearance:none;-webkit-appearance:none;
  padding:12px 40px 12px 14px;border-radius:12px;border:1px solid var(--line2);background-color:var(--bg2);
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='8'><path d='M1 1l5 5 5-5' stroke='%238697ab' stroke-width='1.6' fill='none' stroke-linecap='round'/></svg>");
  background-repeat:no-repeat;background-position:right 14px center;
  color:var(--fg);font-family:var(--mono);font-size:13.5px;cursor:pointer;
}
#labSelect:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 18%,transparent)}
.btn{
  flex:0 0 auto;background:var(--acc);color:#04120a;border:1px solid var(--acc);border-radius:12px;
  padding:12px 18px;font-size:14px;font-weight:700;font-family:var(--sans);cursor:pointer;
}
.btn:hover{filter:brightness(1.08)}
.picker .hint{margin:11px 0 0;font-size:12.5px;color:var(--dim2)}
.labs{margin-top:44px}
.labs-head{display:flex;align-items:baseline;justify-content:space-between;gap:14px;margin-bottom:14px}
.labs h2{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim);margin:0}
.labs .count{font-size:11.5px;color:var(--dim2);font-family:var(--mono)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.mcard{
  display:flex;flex-direction:column;gap:11px;padding:20px;border-radius:16px;border:1px solid var(--line);
  background:linear-gradient(180deg,color-mix(in srgb,var(--panel) 85%,transparent),var(--panel));
  color:var(--fg);text-decoration:none;
  transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease;
}
.mcard:hover{transform:translateY(-3px);border-color:var(--acc);text-decoration:none;box-shadow:var(--shadow)}
.mcard-head{display:flex;align-items:center;justify-content:space-between;gap:10px}
.m-ip{font-family:var(--mono);font-size:12px;color:var(--dim)}
.pill{font-size:10px;letter-spacing:.1em;text-transform:uppercase;padding:3px 9px;border-radius:99px;border:1px solid var(--line2);color:var(--dim);white-space:nowrap}
.pill.ok{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 42%,transparent);background:color-mix(in srgb,var(--acc) 10%,transparent)}
.pill.warn{color:var(--amber);border-color:color-mix(in srgb,var(--amber) 42%,transparent);background:color-mix(in srgb,var(--amber) 10%,transparent)}
.m-name{margin:0;font-size:23px;letter-spacing:-.02em}
.m-role{font-family:var(--mono);font-size:11.5px;color:var(--acc);margin:-6px 0 0}
.m-sum{margin:0;color:var(--dim);font-size:13.5px;line-height:1.55;flex:1}
.m-tags{display:flex;flex-wrap:wrap;gap:6px}
.m-tags span{font-size:10.5px;font-family:var(--mono);color:var(--dim);border:1px solid var(--line);border-radius:6px;padding:2px 7px;background:var(--bg2)}
.m-foot{display:flex;align-items:center;justify-content:space-between;gap:10px;border-top:1px solid var(--line);padding-top:12px;font-size:12px;color:var(--dim2)}
.m-go{color:var(--link);font-weight:650;white-space:nowrap}
.mcard:hover .m-go{color:var(--acc)}
.labsearch{position:relative;max-width:760px;margin:2px 0 20px}
#labSearch{
  width:100%;padding:12px 42px;border-radius:12px;border:1px solid var(--line2);background-color:var(--bg2);
  background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='14' height='14'><circle cx='6' cy='6' r='4.3' fill='none' stroke='%238697ab' stroke-width='1.6'/><path d='M9.4 9.4L13 13' stroke='%238697ab' stroke-width='1.6' stroke-linecap='round'/></svg>");
  background-repeat:no-repeat;background-position:left 14px center;
  color:var(--fg);font-family:var(--mono);font-size:13.5px;
}
#labSearch:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 18%,transparent)}
#labSearch::placeholder{color:var(--dim2)}
#labSearch::-webkit-search-cancel-button,#labSearch::-webkit-search-decoration{-webkit-appearance:none}
.search-clear{
  position:absolute;right:8px;top:50%;transform:translateY(-50%);
  background:none;border:0;color:var(--dim2);font-size:17px;line-height:1;cursor:pointer;
  padding:5px 8px;border-radius:8px;font-family:var(--sans);
}
.search-clear:hover{color:var(--fg)}
.search-empty{margin:-8px 0 16px;color:var(--amber);font-size:13px;font-family:var(--mono)}
.mcard[hidden]{display:none}
body.home-body .topbar .icon-btn{margin-left:auto}
.home-foot{margin-top:52px;padding-top:20px;border-top:1px solid var(--line);color:var(--dim2);font-size:12.5px;display:flex;flex-wrap:wrap;gap:14px;justify-content:space-between}
@media (max-width:560px){
  main.home{padding:30px 16px 70px}
  .grid{grid-template-columns:1fr}
}
"""

HOME_JS = r"""
(function(){
  "use strict";
  var root=document.documentElement;
  var THEME_KEY="oscp-theme";
  function setTheme(t){root.setAttribute("data-theme",t);try{localStorage.setItem(THEME_KEY,t)}catch(e){}}
  var saved=null;try{saved=localStorage.getItem(THEME_KEY)}catch(e){}
  if(!saved){saved=window.matchMedia&&window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}
  setTheme(saved);
  document.getElementById("themeBtn").addEventListener("click",function(){
    setTheme(root.getAttribute("data-theme")==="dark"?"light":"dark");
  });

  var form=document.getElementById("picker");
  var sel=document.getElementById("labSelect");
  var toast=document.getElementById("toast"),tt=null;
  function say(msg){
    toast.textContent=msg;toast.classList.add("show");
    clearTimeout(tt);tt=setTimeout(function(){toast.classList.remove("show")},1600);
  }
  function go(){
    var v=sel.value;
    if(!v){say("Pick a lab first");return;}
    window.location.href=v;
  }
  sel.addEventListener("change",go);
  form.addEventListener("submit",function(e){e.preventDefault();go();});
  /* ---- lab search: filters the cards and the dropdown ------------------ */
  var searchInput=document.getElementById("labSearch");
  if(searchInput){
    var cards=[].slice.call(document.querySelectorAll(".mcard"));
    var opts=[].slice.call(sel.querySelectorAll("option"));
    var countEl=document.querySelector(".labs .count");
    var baseCount=countEl?countEl.textContent:"";
    var emptyEl=document.getElementById("searchEmpty");
    var termEl=document.getElementById("searchTerm");
    var clearBtn=document.querySelector(".search-clear");
    function norm(s){return (s||"").toLowerCase().replace(/\s+/g," ").trim();}
    function apply(q){
      q=norm(q);
      var shown=0;
      cards.forEach(function(c){
        var hay=norm(c.getAttribute("data-search")||c.textContent);
        var hit=!q||hay.indexOf(q)!==-1;
        c.hidden=!hit;
        if(hit){shown++;}
      });
      opts.forEach(function(o){
        if(o.value){o.hidden=!!q&&norm(o.getAttribute("data-search")||o.textContent).indexOf(q)===-1;}
      });
      if(countEl){countEl.textContent=q?(shown+" / "+baseCount):baseCount;}
      if(emptyEl){emptyEl.hidden=!(q&&shown===0);if(termEl){termEl.textContent=q;}}
      if(clearBtn){clearBtn.hidden=!q;}
      try{
        var u=new URL(window.location.href);
        if(q){u.searchParams.set("q",q);}else{u.searchParams.delete("q");}
        history.replaceState(null,"",u);
      }catch(err){}
    }
    searchInput.addEventListener("input",function(){apply(searchInput.value);});
    searchInput.addEventListener("search",function(){apply(searchInput.value);});
    if(clearBtn){clearBtn.addEventListener("click",function(){searchInput.value="";apply("");searchInput.focus();});}
    document.addEventListener("keydown",function(e){
      var typing=/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if(e.key==="Escape"&&document.activeElement===searchInput){searchInput.value="";apply("");searchInput.blur();}
      if(e.key==="/"&&!typing){e.preventDefault();searchInput.focus();}
    });
    var q0="";try{q0=new URL(window.location.href).searchParams.get("q")||"";}catch(err){}
    if(q0){searchInput.value=q0;apply(q0);}
  }else{
    document.addEventListener("keydown",function(e){
      var typing=/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if(e.key==="/"&&!typing){e.preventDefault();sel.focus();}
    });
  }
})();
"""

HOME_TEMPLATE = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSCP lab walkthroughs — select a lab</title>
<meta name="description" content="Step-by-step OSCP lab walkthroughs. Pick a lab to open its full chain: commands, raw output and reasoning.">
<meta property="og:type" content="website">
<meta property="og:title" content="OSCP lab walkthroughs — select a lab">
<meta property="og:description" content="Step-by-step OSCP lab walkthroughs. Pick a lab to open its full chain.">
<meta name="color-scheme" content="dark light">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>💀</text></svg>">
<style>%%CSS%%%%HOMECSS%%</style>
</head>
<body class="home-body">
<header class="topbar">
  <div class="brand"><span class="dot"></span>OSCP<span class="slash">/</span><span class="brand-sub">labs</span></div>
  <button class="icon-btn" id="themeBtn" type="button" aria-label="Toggle colour theme" title="Toggle theme">◐</button>
</header>

<main class="home">
  <section class="home-hero">
    <div class="eyebrow">OSCP lab walkthroughs</div>
    <h1>Select a lab.<br><span class="dim">Read the whole chain.</span></h1>
    <p class="lede">
      Every host I have taken apart in the lab, written up as it happened — the commands, the output
      they produced, and the reasoning in between. Pick a lab to open its walkthrough.
    </p>

    <form class="picker" id="picker" action="%%FIRST%%">
      <label for="labSelect">Lab</label>
      <div class="picker-row">
        <select id="labSelect" name="machine">
          <option value="" selected disabled>Select a lab…</option>
%%OPTIONS%%
        </select>
        <button class="btn" type="submit">Open lab →</button>
      </div>
      <p class="hint">Choosing a lab opens its page immediately. Press <b>/</b> to search.</p>
    </form>
  </section>

  <section class="labs" id="labs">
    <div class="labs-head">
      <h2>Labs</h2>
      <span class="count">%%COUNT%%</span>
    </div>
    <div class="labsearch" role="search">
      <input id="labSearch" type="search" placeholder="Search labs — ip, name, os, cve, technique…"
             autocomplete="off" spellcheck="false" aria-label="Search labs">
      <button class="search-clear" type="button" aria-label="Clear search" hidden>&times;</button>
    </div>
    <p class="search-empty" id="searchEmpty" aria-live="polite" hidden>No lab matches &ldquo;<span id="searchTerm"></span>&rdquo; — try an ip, os, cve or technique.</p>
    <div class="grid">
%%CARDS%%
    </div>
  </section>

  <footer class="home-foot">
    <span>Authorised lab environment · flags and credentials are lab-specific</span>
    <span><a href="%%REPO%%">source on GitHub</a> · built %%DATE%%</span>
  </footer>
</main>

<div id="toast" role="status" aria-live="polite"></div>
<script>%%HOMEJS%%</script>
</body>
</html>
"""


def _out_rel(mach: dict) -> str:
    return mach["out"].relative_to(ROOT).as_posix()


def _opt_label(mach: dict) -> str:
    return mach["card"].get("option") or f'{mach["ip"]} — {mach["name"]}'


def _haystack(m: dict) -> str:
    """Searchable text for one lab: identity, card copy, badges, meta and chain steps."""
    c = m["card"]
    parts = [m["ip"], m["name"], c["status_text"], c["summary"], c["foot"]]
    parts += list(c["tags"])
    parts += [b[1] for b in m.get("badges", [])]
    parts += [f"{k} {v}" for k, v in m.get("meta", [])]
    for _step in m.get("chain", []):
        parts.extend(re.sub(r"<[^>]+>", " ", s) for s in _step[1:3])
    return html.escape(re.sub(r"\s+", " ", " ".join(parts)).strip().lower(), quote=True)


def build_home_options() -> str:
    return "\n".join(
        f'          <option value="{_out_rel(m)}" data-search="{_haystack(m)}">'
        f'{_opt_label(m)}</option>' for m in LABS
    )


def build_home_cards() -> str:
    cards = []
    for m in LABS:
        c = m["card"]
        parts = [
            f'<div class="mcard-head"><span class="m-ip">{m["ip"]}</span>'
            f'<span class="pill {c["status"]}">{c["status_text"]}</span></div>',
            f'<h3 class="m-name">{m["name"]}</h3>',
        ]
        if c.get("role"):
            parts.append(f'<p class="m-role">{c["role"]}</p>')
        parts.append(f'<p class="m-sum">{c["summary"]}</p>')
        parts.append('<div class="m-tags">' + "".join(f"<span>{t}</span>" for t in c["tags"]) + '</div>')
        parts.append(
            f'<div class="m-foot"><span>{c["foot"]}</span>'
            '<span class="m-go">Open lab →</span></div>'
        )
        cards.append(
            f'      <a class="mcard" href="{_out_rel(m)}" data-search="{_haystack(m)}">'
            + "".join(parts) + "</a>"
        )
    return "\n".join(cards)


def build_home() -> str:
    return (
        HOME_TEMPLATE.replace("%%CSS%%", CSS)
        .replace("%%HOMECSS%%", HOME_CSS)
        .replace("%%HOMEJS%%", HOME_JS)
        .replace("%%OPTIONS%%", build_home_options())
        .replace("%%CARDS%%", build_home_cards())
        .replace("%%FIRST%%", _out_rel(LABS[0]))
        .replace("%%COUNT%%", f"{len(LABS)} labs")
        .replace("%%REPO%%", REPO)
        .replace("%%DATE%%", datetime.date.today().strftime("%d %B %Y"))
    )


def build_meta(mach: dict) -> str:
    return "\n".join(
        f'      <div class="meta-line"><span>{k}</span><span>{v}</span></div>'
        for k, v in mach["meta"]
    )


def build_badges(mach: dict) -> str:
    out = []
    for kind, text in mach["badges"]:
        cls = "badge " + kind if kind else "badge"
        out.append(f'        <span class="{cls}">{text}</span>')
    return "\n".join(out)


def build_flags(mach: dict) -> str:
    out = []
    for label, value in mach["flags"]:
        out.append(
            '        <div class="flag">\n'
            f'          <div class="k">{label}</div>\n'
            f'          <div class="v" data-value="{value}">'
            '<span class="masked">••••••••••••••••••••••••••••••••</span></div>\n'
            '          <button class="reveal" type="button">reveal</button>\n'
            '        </div>'
        )
    return "\n".join(out)


def build_page(mach: dict) -> str:
    return (
        TEMPLATE.replace("%%CSS%%", CSS)
        .replace("%%JS%%", JS)
        .replace("%%PKEY%%", mach["pkey"])
        .replace("%%NAV%%", build_nav(mach))
        .replace("%%CHAIN%%", build_chain(mach))
        .replace("%%BODY%%", build_body(mach))
        .replace("%%METAROWS%%", build_meta(mach))
        .replace("%%BADGES%%", build_badges(mach))
        .replace("%%FLAGS%%", build_flags(mach))
        .replace("%%TITLE%%", mach["title"])
        .replace("%%DESC%%", mach["desc"])
        .replace("%%OGDESC%%", mach["ogdesc"])
        .replace("%%LEDE%%", mach["lede"])
        .replace("%%NAME%%", mach["name"])
        .replace("%%IP%%", mach["ip"])
        .replace("%%HOME%%", mach["home"])
        .replace("%%CHN%%", str(len(mach["chapters"])))
        .replace("%%REPO%%", REPO)
        .replace("%%DATE%%", datetime.date.today().strftime("%d %B %Y"))
    )



REDIRECT_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSCP lab walkthroughs</title>
<link rel="canonical" href="main.html">
<meta name="robots" content="noindex">
<meta http-equiv="refresh" content="0; url=main.html">
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#0a0e13;color:#8697ab;font-family:system-ui,-apple-system,sans-serif;font-size:15px}
  a{color:#3fb950}
</style>
</head>
<body>
<p>Opening the <a href="main.html">lab index</a>…</p>
<script>location.replace("main.html"+location.search+location.hash);</script>
</body>
</html>
"""


def audit_labs() -> None:
    """Warn about lab folders the main page would not list."""
    listed = {lab["dir"].resolve() for lab in LABS}
    on_disk = {p.resolve() for p in LABS_DIR.iterdir() if p.is_dir()}
    for missing in sorted(on_disk - listed):
        print(f"WARNING: labs/{missing.name}/ has no entry in LABS - main.html will not list it")
    for lab in LABS:
        if not lab["dir"].is_dir():
            print(f"ERROR: '{lab['slug']}' points at a missing directory: {lab['dir']}")
        for _cid, _num, _title, _sub, path in lab["chapters"]:
            if not path.is_file():
                print(f"ERROR: {lab['slug']}: missing chapter {path.name}")


def main() -> None:
    audit_labs()
    for lab in LABS:
        html_out = build_page(lab)
        lab["out"].parent.mkdir(parents=True, exist_ok=True)
        lab["out"].write_text(html_out, encoding="utf-8")
        rel = lab["out"].relative_to(ROOT)
        print(f"wrote {rel} ({lab['out'].stat().st_size/1024:.1f} KB, "
              f"{html_out.count(chr(10))} lines)")

    home = build_home()
    HOME_OUT.write_text(home, encoding="utf-8")
    print(f"wrote {HOME_OUT.name} ({HOME_OUT.stat().st_size/1024:.1f} KB, "
          f"{home.count(chr(10))} lines)")

    REDIRECT_OUT.write_text(REDIRECT_TEMPLATE, encoding="utf-8")
    print(f"wrote {REDIRECT_OUT.name} (redirect -> {HOME_OUT.name})")


if __name__ == "__main__":
    main()
