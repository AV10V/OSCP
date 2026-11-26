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
MS02 = LABS_DIR / "ad-oscp-ms02"
ADCOMPLETE = LABS_DIR / "ad-oscp-exam-complete"
GUST = LABS_DIR / "192.168.137.151-gust"
WINSNMP = LABS_DIR / "192.168.103.145-snmp-mouse"
GITEXP = LABS_DIR / "192.168.161.144-git-exposure"
AERO = LABS_DIR / "192.168.150.143-aerospike-screen"
OSCPMOUSE = LABS_DIR / "192.168.133.155-oscp-mouse"
VESTA = LABS_DIR / "192.168.161.156-vesta-snmp"
CHARLIE = LABS_DIR / "192.168.161.157-charlie"

# Lab index: one card per lab, plus a select that redirects to that lab page.
# main.html is the entry point; index.html is a redirect so the Pages root keeps working.
HOME_OUT = ROOT / "main.html"
REDIRECT_OUT = ROOT / "index.html"

# Standalone reference page: every command on one page, built from markdown.
CHEATSHEET_MD = DOCS / "oscp-cheatsheet.md"
CHEATSHEET_OUT = ROOT / "cheatsheet.html"

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
        "slug": "oscp-exam-ms02",
        "out": MS02 / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-oscp-exam-ms02",
        "card": {
            "status": "warn",
            "status_text": "in progress",
            "role": "MS02 → DC01",
            "summary": "Second pass at <code>oscp.exam</code> with DC01 reachable directly: WinRM as "
                       "<code>celia.almeda</code>, SQL sysadmin ruled out, zero ACL edges in "
                       "BloodHound → roast <code>sql_svc</code>.",
            "tags": ["Server 2019", "Active Directory", "MSSQL", "Kerberoast"],
            "foot": "MS02 foothold · DC01 open",
        },
        "dir": MS02,
        "dir_rel": "labs/ad-oscp-ms02",
        "ip": "10.10.152.0/24",
        "name": "oscp.exam · MS02",
        "title": "10.10.152.142 — MS02 · OSCP walkthrough",
        "desc": "Interactive walkthrough of the oscp.exam AD set from a position where DC01 is "
                "reachable: WinRM foothold, MSSQL ruled out, BloodHound analysis to a single "
                "Kerberoastable service account.",
        "ogdesc": "celia.almeda → WinRM → no SeImpersonate, no SQL sysadmin, no ACL edges → "
                  "Kerberoast sql_svc.",
        "lede": "The same directory as the earlier AD set, seen from a network where the domain "
                "controller finally answers directly. Two credentials, four protocols, and every "
                "local path closed by the token itself — which leaves one stale service account.",
        "badges": [
            ("", "Server 2019 · build 19041"),
            ("", "oscp.exam"),
            ("warn", "SMB signing off (MS02)"),
            ("ok", "DC01 direct"),
            ("warn", "no SeImpersonate"),
            ("warn", "sysadmin = 0"),
        ],
        "meta": [
            ("Domain", "oscp.exam"),
            ("MS02", "10.10.152.142"),
            ("DC01", "10.10.152.140"),
            ("Domain SID", "…-2610934713-1581164095-2706428072"),
            ("Access", "WinRM · celia.almeda"),
            ("Result", "MS02 foothold"),
        ],
        "flags": [],
        "chain": [
            ("01", "Recon", "no shares, <code>signing:False</code>", "#ch-01"),
            ("02", "WinRM", "<code>celia.almeda</code>, medium integrity", "#ch-02"),
            ("03", "MSSQL", "two logins, <code>sysadmin = 0</code>", "#ch-03"),
            ("04", "Domain", "DC01 direct, <code>Users</code> share", "#ch-04"),
            ("05", "Graph", "zero outbound ACEs", "#ch-05"),
            ("06", "Ruled out", "seven paths, closed with evidence", "#ch-06"),
            ("07", "Next", "roast <code>sql_svc</code>", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Same directory, new network position",
             MS02 / "01-reconnaissance.md"),
            ("ch-02", "02", "Foothold", "WinRM, and the token that proves nothing",
             MS02 / "02-foothold.md"),
            ("ch-03", "03", "MSSQL", "Two logins, <code>sysadmin = 0</code>",
             MS02 / "03-mssql.md"),
            ("ch-04", "04", "Domain reconnaissance", "DC01 direct, and a Kerberoast that did not run",
             MS02 / "04-domain-recon.md"),
            ("ch-05", "05", "BloodHound", "Zero outbound edges, and one stale service account",
             MS02 / "05-bloodhound.md"),
            ("ch-06", "06", "What is ruled out", "Seven paths, each closed with evidence",
             MS02 / "06-ruled-out.md"),
            ("ch-07", "07", "Next actions", "Why <code>sql_svc</code>, and what runs next",
             MS02 / "07-next-actions.md"),
        ] + REFERENCE,
    },
    {
        "slug": "oscp-exam-ad",
        "out": ADCOMPLETE / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-oscp-exam-ad",
        "card": {
            "status": "ok",
            "status_text": "complete",
            "role": "MS01 \u2192 MS02 \u2192 DC01",
            "summary": "The whole AD set end to end: SYSTEM on MS01, the NL$ cache cracked to "
                       "<code>web_svc</code>, a ligolo tunnel into <code>10.10.133.0/24</code>, "
                       "<code>sql_svc</code> kerberoast \u2192 MSSQL \u2192 stale hives \u2192 "
                       "<code>tom_admin</code> \u2192 DC01.",
            "tags": ["Active Directory", "Kerberoast", "MSSQL", "SeImpersonate", "ligolo"],
            "foot": "DC01 proof.txt \u00b7 Domain Admins",
        },
        "dir": ADCOMPLETE,
        "dir_rel": "labs/ad-oscp-exam-complete",
        "ip": "10.10.133.0/24",
        "name": "oscp.exam AD",
        "title": "oscp.exam \u2014 AD complete: MS01 \u2192 MS02 \u2192 DC01 \u00b7 OSCP walkthrough",
        "desc": "Complete OSCP Active Directory walkthrough: WinRM foothold, SeImpersonate to SYSTEM, "
                "NL$ cache cracking, a ligolo-ng pivot, sql_svc kerberoast, MSSQL xp_cmdshell, stale "
                "windows.old hives and pass-the-hash to the domain controller. Full commands and scripts.",
        "ogdesc": "MS01 SYSTEM \u2192 NL$ cache \u2192 web_svc \u2192 ligolo \u2192 sql_svc kerberoast \u2192 "
                   "MSSQL \u2192 windows.old hives \u2192 tom_admin \u2192 DC01 proof.txt.",
        "lede": "A domain behind a dual-homed member server, taken end to end. The interesting part is "
                "not the SYSTEM shell \u2014 it is what a member server keeps on disk: a cached domain "
                "credential, and a previous Windows build whose local accounts were never retired.",
        "badges": [
            ("", "Server 2019 \u00b7 build 19041"),
            ("", "oscp.exam"),
            ("warn", "SMB signing off"),
            ("ok", "MS01 SYSTEM"),
            ("ok", "MSSQL sysadmin"),
            ("ok", "Domain Admins \u00b7 flag"),
        ],
        "meta": [
            ("Domain", "oscp.exam"),
            ("MS01", "10.10.133.153"),
            ("MS02", "10.10.133.154"),
            ("DC01", "10.10.133.152"),
            ("Pivot", "ligolo-ng"),
            ("Result", "Domain Admins"),
        ],
        "flags": [
            ("proof.txt \u00b7 as tom_admin", "captured \u2014 see chapter 07"),
        ],
        "chain": [
            ("01", "Recon", "one routable host, two networks", "#ch-01"),
            ("02", "WinRM", "<code>OSCP\\eric.wallows</code>", "#ch-02"),
            ("03", "SYSTEM", "<code>SeImpersonate</code> \u2192 SYSTEM", "#ch-03"),
            ("04", "NL$ cache", "<code>web_svc:Diamond1</code>", "#ch-04"),
            ("05", "Pivot", "ligolo \u2192 <code>10.10.133.0/24</code>", "#ch-05"),
            ("06", "MS02", "kerberoast \u2192 MSSQL \u2192 hives", "#ch-06"),
            ("07", "DC01", "<code>tom_admin</code> \u2192 <code>proof.txt</code>", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "One routable host, two networks",
             ADCOMPLETE / "01-reconnaissance.md"),
            ("ch-02", "02", "Foothold", "WinRM as eric.wallows",
             ADCOMPLETE / "02-foothold.md"),
            ("ch-03", "03", "Privilege escalation", "SeImpersonate to SYSTEM, in detail",
             ADCOMPLETE / "03-privilege-escalation.md"),
            ("ch-04", "04", "Credentials", "LSASS, the NL$ cache, and web_svc",
             ADCOMPLETE / "04-credentials.md"),
            ("ch-05", "05", "Pivot", "ligolo-ng into 10.10.133.0/24",
             ADCOMPLETE / "05-pivot.md"),
            ("ch-06", "06", "MS02", "Kerberoast, MSSQL, and the stale hives",
             ADCOMPLETE / "06-ms02.md"),
            ("ch-07", "07", "DC01", "tom_admin, the flag, and what is proved",
             ADCOMPLETE / "07-dc01.md"),
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
            "summary": "Unauthenticated Aerospike 5.1.0.1 UDF → <code>aero</code> shell, pty on the "
                       "allowlisted port 3000 → setuid screen 4.5.0 → root.",
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
            ("warn", "egress :3000 only"),
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
            ("04", "UDF", "<code>io.popen</code> → <code>aero</code>, pty on <code>:3000</code>", "#ch-04"),
            ("05", "Enum", "PwnKit out, <code>screen-4.5.0</code> in", "#ch-05"),
            ("06", "screen", "<code>libhax.so</code> → <code>ld.so.preload</code> → root", "#ch-06"),
            ("07", "proof.txt", "root, then cleanup", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Ten ports, and why <em>filtered</em> is not <em>closed</em>",
             AERO / "01-reconnaissance.md"),
            ("ch-02", "02", "Web enumeration", "Pico CMS under /index/, and the vhost that lies",
             AERO / "02-web-enumeration.md"),
            ("ch-03", "03", "Aerospike", "Naming the daemon, reading 5.1.0.1 off the wire",
             AERO / "03-aerospike.md"),
            ("ch-04", "04", "Foothold", "Lua that runs shell — and the port allowlist behind it",
             AERO / "04-foothold.md"),
            ("ch-05", "05", "Enumeration", "Two refutations, one unreadable cron, no compiler",
             AERO / "05-enumeration.md"),
            ("ch-06", "06", "Privilege escalation", "Payload: get, modify, build, deliver, trigger — by machine",
             AERO / "06-privilege-escalation.md"),
            ("ch-07", "07", "Flags &amp; cleanup", "Proof, artefact removal, lessons",
             AERO / "07-flags-and-cleanup.md"),
        ] + REFERENCE,
    },
    {
        "slug": "oscp-mouse",
        "out": OSCPMOUSE / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-oscp-mouse",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "TCP/9099 Mobile Mouse Server 3.6.4 (CVE-2023-31902, no auth) → shell as a "
                       "standard user → Users-writable LocalSystem service binary → SYSTEM → WinRM.",
            "tags": ["Windows 10", "Mobile Mouse", "CVE-2023-31902", "Service ACL"],
            "foot": "Tim → SYSTEM · proof.txt",
        },
        "dir": OSCPMOUSE,
        "dir_rel": "labs/192.168.133.155-oscp-mouse",
        "ip": "192.168.133.155",
        "name": "oscp-mouse",
        "title": "192.168.133.155 — oscp-mouse · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: an unauthenticated Mobile Mouse "
                "Server on TCP 9099 (CVE-2023-31902), then a MilleGPG service whose binary and "
                "service ACL are writable by BUILTIN\\Users. Full commands, reasoning and raw output.",
        "ogdesc": "9099 Mobile Mouse RCE → shell as OSCP\\Tim → writable LocalSystem service → "
                  "SYSTEM → proof.txt.",
        "lede": "A workstation running a phone-as-a-mouse server that will type anything the network "
                "sends it. That is a shell as whoever is logged in — a standard user. The escalation "
                "is not a CVE: it is a third-party service, running as LocalSystem, whose binary any "
                "local user may rewrite and whose service object any local user may reconfigure.",
        "badges": [
            ("", "Windows 10 Pro · 19045.2251"),
            ("warn", "9099/tcp no auth"),
            ("warn", "CVE-2023-31902"),
            ("warn", "Users:(M) on service binary"),
            ("warn", "no SeImpersonate"),
            ("ok", "SYSTEM · proof.txt"),
        ],
        "meta": [
            ("Host", "oscp (workgroup OSCP)"),
            ("IP", "192.168.133.155"),
            ("OS", "Windows 10 Pro · build 19045.2251"),
            ("TCP", "80, 5986, 7680, 9099, 9999, 35913"),
            ("Product", "Mobile Mouse 3.6.4 · MilleGPG5"),
            ("Result", "SYSTEM → local admin hacker"),
        ],
        "flags": [
            ("proof.txt · as NT AUTHORITY\\SYSTEM", "4a456f445abc93450df024fc1b57bc23"),
        ],
        "chain": [
            ("01", "9099", "<code>unknown</code> → <code>Mobile Mouse Server</code>", "#ch-01"),
            ("02", "CVE-2023-31902", "no password, keystrokes as the desktop user", "#ch-02"),
            ("03", "Tim", "shell, medium integrity", "#ch-03"),
            ("04", "PowerUp", "<code>CanRestart: True</code> on GPGOrchestrator", "#ch-04"),
            ("05", "SYSTEM", "<code>sc config binPath=</code> · 1053 = it ran", "#ch-05"),
            ("06", "proof.txt", "token filter off → WinRM 5986", "#ch-06"),
            ("07", "Cleanup", "restore the service, delete the account", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Six ports, and the one nmap calls <em>unknown</em>",
             OSCPMOUSE / "01-reconnaissance.md"),
            ("ch-02", "02", "Mobile Mouse", "CVE-2023-31902 and its real precondition",
             OSCPMOUSE / "02-mobile-mouse.md"),
            ("ch-03", "03", "Foothold", "<code>mobile_mouse_rce</code> → shell as Tim",
             OSCPMOUSE / "03-foothold.md"),
            ("ch-04", "04", "Enumeration", "Seatbelt for identity, PowerUp for the service",
             OSCPMOUSE / "04-enumeration.md"),
            ("ch-05", "05", "Privilege escalation", "Users:(M) + DC/RP/DT → <code>binPath</code>",
             OSCPMOUSE / "05-privilege-escalation.md"),
            ("ch-06", "06", "Loot &amp; admin shell", "proof.txt, token filtering, WinRM over 5986",
             OSCPMOUSE / "06-loot-and-admin-shell.md"),
            ("ch-07", "07", "Cleanup &amp; lessons", "Restore the service; what found what",
             OSCPMOUSE / "07-cleanup-and-lessons.md"),
        ] + REFERENCE,
    },
    {
        "slug": "vesta-snmp",
        "out": VESTA / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-vesta-snmp",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "UDP/161 SNMP extend publishes a cleartext panel password → VestaCP 0.9.8-27 "
                       "→ mailbox forwarding field runs as root.",
            "tags": ["Ubuntu 18.04", "SNMP", "VestaCP", "Command Injection"],
            "foot": "local.txt + proof.txt",
        },
        "dir": VESTA,
        "dir_rel": "labs/192.168.161.156-vesta-snmp",
        "ip": "192.168.161.156",
        "name": "vesta",
        "title": "192.168.161.156 — vesta · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: an SNMP extend entry that publishes "
                "a cleartext panel password, then a VestaCP mailbox forwarding field that executes as "
                "root. Full commands, reasoning and raw output.",
        "ogdesc": "UDP/161 nsExtendConfigTable → jack's password → VestaCP 0.9.8-27 → v_fwd "
                  "injection → root.",
        "lede": "A hosting server with sixteen TCP ports, a full mail stack and a control panel — "
                "and an entry point on a UDP port nobody scans. The host publishes its own password "
                "in the SNMP MIB, and the panel then runs an unprivileged user's mailbox forwarding "
                "address as root.",
        "badges": [
            ("", "Ubuntu 18.04"),
            ("", "Exim 4.90_1 · Dovecot"),
            ("", "VestaCP 0.9.8-27"),
            ("warn", "udp/161 snmpd public"),
            ("warn", "v_fwd → sudo"),
            ("ok", "root · 2 flags"),
        ],
        "meta": [
            ("Host", "lab-pwk2-student-cl6-156"),
            ("IP", "192.168.161.156"),
            ("OS", "Ubuntu 18.04 LTS"),
            ("TCP", "21, 22, 25, 53, 80, 110, 143, 465, 587, 993, 995, 2525, 3306, 8080, 8083, 8443"),
            ("UDP", "53, 161"),
            ("Result", "root"),
        ],
        "flags": [
            ("local.txt · as jack", "9cfca959e54738e70905a4024d16a44a"),
            ("proof.txt · as root", "d4640a77ca31e0ab126751f98e819888"),
        ],
        "chain": [
            ("01", "UDP 161", "snmpd · community <code>public</code>", "#ch-01"),
            ("02", "Extend leak", "<code>nsExtendConfigTable</code> → <code>jack:3PUKs…</code>", "#ch-03"),
            ("03", "Panel", "0.9.8-27 · session token", "#ch-04"),
            ("04", "Upload", "webshell in <code>public_html</code> as jack", "#ch-05"),
            ("05", "v_fwd", "<code>sudo v-edit-mail-account</code>", "#ch-06"),
            ("06", "root", "<code>proof.txt</code>", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Sixteen TCP ports, and the UDP one that mattered",
             VESTA / "01-reconnaissance.md"),
            ("ch-02", "02", "Web enumeration", "Two servers, one panel, one false positive",
             VESTA / "02-web-enumeration.md"),
            ("ch-03", "03", "SNMP", "The host publishes its own password", VESTA / "03-snmp.md"),
            ("ch-04", "04", "Panel access", "A session, and what a session is worth",
             VESTA / "04-panel-access.md"),
            ("ch-05", "05", "Foothold", "File write into a docroot, execution as the vhost user",
             VESTA / "05-foothold.md"),
            ("ch-06", "06", "Privilege escalation", "A forwarding address that runs as root",
             VESTA / "06-privilege-escalation.md"),
            ("ch-07", "07", "Flags &amp; cleanup", "Proof, debris, remediation, lessons",
             VESTA / "07-flags-and-cleanup.md"),
        ] + REFERENCE,
    },
    {
        "slug": "charlie",
        "out": CHARLIE / "index.html",
        "home": "../../main.html",
        "pkey": "oscp-progress-charlie",
        "card": {
            "status": "ok",
            "status_text": "owned",
            "summary": "Anonymous FTP leaks document authors → case-flipped password → "
                       "Usermin 1.820 GnuPG RCE → tar wildcard in a root cron → root.",
            "tags": ["Ubuntu 22.04", "Usermin", "FTP", "tar wildcard"],
            "foot": "local.txt + proof.txt",
        },
        "dir": CHARLIE,
        "dir_rel": "labs/192.168.161.157-charlie",
        "ip": "192.168.161.157",
        "name": "charlie",
        "title": "192.168.161.157 — charlie · OSCP walkthrough",
        "desc": "Interactive step-by-step OSCP lab walkthrough: anonymous FTP leaks document "
                "authors, the password is the username with the case flipped, Usermin 1.820's "
                "GnuPG module gives code execution, and a bare `*` in a root cron job gives root. "
                "Full commands, reasoning and raw output.",
        "ogdesc": "Anonymous FTP → exiftool dc:creator → cassie:cassie → Usermin 1.820 GnuPG "
                  "RCE → DenyUsers removed → tar --checkpoint-action → root.",
        "lede": "A box that punishes two assumptions: that MiniServ on port 20000 is Webmin, and "
                "that a proven-correct SSH key must work. Between them sits a per-user panel whose "
                "GnuPG module pastes a key name into a shell, and a cron job that runs tar with a "
                "bare wildcard inside a directory the user owns.",
        "badges": [
            ("", "Ubuntu 22.04.1"),
            ("", "vsftpd 3.0.5 · anon"),
            ("", "OpenSSH 8.9p1"),
            ("warn", "Usermin 1.820"),
            ("warn", "DenyUsers cassie"),
            ("ok", "root · 2 flags"),
        ],
        "meta": [
            ("Host", "lab-pwk2-…-charlie-240-111"),
            ("IP", "192.168.161.157"),
            ("OS", "Ubuntu 22.04.1"),
            ("TCP", "21, 22, 80, 20000"),
            ("Result", "root"),
        ],
        "flags": [
            ("local.txt · as cassie", "9c3006bdea469fa32aace984f50acc19"),
            ("proof.txt · as root", "06fc3530c91d86d66a81d84a116f4eb0"),
        ],
        "chain": [
            ("01", "FTP 21", "anonymous <code>/backup</code> · 5 PDFs", "#ch-02"),
            ("02", "Metadata", "<code>dc:creator</code> → cassie · mark · robert", "#ch-02"),
            ("03", "Panel", "Usermin 1.820 · <code>/gnupg/</code>", "#ch-03"),
            ("04", "RCE", "<code>edit_key.cgi</code> · as cassie", "#ch-04"),
            ("05", "tar", "<code>/opt/admin</code> · <code>--checkpoint</code>", "#ch-06"),
            ("06", "root", "<code>proof.txt</code>", "#ch-07"),
        ],
        "chapters": [
            ("ch-01", "01", "Reconnaissance", "Four ports, and the banner that lies",
             CHARLIE / "01-reconnaissance.md"),
            ("ch-02", "02", "Anonymous FTP", "Five PDFs, three authors, nine guesses",
             CHARLIE / "02-anonymous-ftp-and-pdf-metadata.md"),
            ("ch-03", "03", "Usermin &amp; GnuPG", "The module that pastes a name into a shell",
             CHARLIE / "03-usermin-and-gnupg.md"),
            ("ch-04", "04", "Foothold", "Fixing EDB 50234, proving execution without a shell",
             CHARLIE / "04-foothold.md"),
            ("ch-05", "05", "SSH denied", "A 91-byte key and a pre-auth deny list",
             CHARLIE / "05-ssh-denied.md"),
            ("ch-06", "06", "Privilege escalation", "A bare <code>*</code> in a root cron job",
             CHARLIE / "06-privilege-escalation.md"),
            ("ch-07", "07", "Flags &amp; cleanup", "Proof, debris, remediation, lessons",
             CHARLIE / "07-flags-and-cleanup.md"),
            ("ch-10", "A", "Appendix", "Every script in full, plus inline payloads",
             CHARLIE / "08-appendix-scripts.md"),
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
        # A relative link in a chapter is relative to the lab directory, not the repo root:
        # scripts/foo.py -> labs/<lab>/scripts/foo.py. '../' still resolves upwards.
        parts = []
        for part in pathlib.PurePosixPath(mach["dir_rel"], href).parts:
            if part == "..":
                if parts:
                    parts.pop()
            elif part != ".":
                parts.append(part)
        return 'href="%s%s"' % (REPO + "/blob/main/" + "/".join(parts), frag)

    return re.sub(r'href="([^"]+)"', repl, text)


# Fenced blocks rendered as "command" cards with a Copy button. Script languages belong here
# because a walkthrough script is something you copy and run, not output to read.
CMD_LANGS = {"bash", "sh", "shell", "console", "zsh", "powershell", "ps1", "ps", "cmd", "bat",
             "dos", "python", "python3", "py"}
FENCE = re.compile(r"^```([^\n`]*)\n(.*?)^```\s*$", re.S | re.M)
FORMATTER = HtmlFormatter(nowrap=True, style="monokai")


def code_block(code: str, lang: str, plain: bool = False) -> str:
    """Render one fenced block as a command or output card."""
    code = code.strip("\n")
    is_cmd = lang.lower() in CMD_LANGS
    label = "command" if is_cmd else "output"
    cls = "block block-cmd" if is_cmd else "block block-out"

    if plain:
        lang = ""

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
.toplink{padding:6px 11px;border-radius:9px;color:var(--dim);font-size:13.5px;white-space:nowrap}
.toplink:hover{background:var(--bg2);color:var(--fg);text-decoration:none}
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
.btn-alt{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  background:transparent;color:var(--fg);border-color:var(--line2);text-decoration:none;
}
.btn-alt:hover{border-color:var(--acc);color:var(--acc);filter:none;text-decoration:none}
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
  <a class="toplink" href="cheatsheet.html">Cheatsheet</a>
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
        <a class="btn btn-alt" href="cheatsheet.html">Cheatsheet →</a>
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


# ---------------------------------------------------------------------------
# Standalone cheatsheet page (cheatsheet.html)
#
# docs/oscp-cheatsheet.md is split on H1/H2 boundaries so the page gets a real table of
# contents, anchor links, and a search filter that hides whole sections. Each fenced block
# goes through the same code_block() renderer as the lab pages, so commands keep a Copy
# button and identical highlighting.
# ---------------------------------------------------------------------------
CHEATSHEET_CSS = r"""
/* ---------- cheatsheet ---------- */
.topnav{display:flex;gap:6px;margin-left:6px;align-items:center}
.topnav a{padding:6px 11px;border-radius:9px;color:var(--dim);font-size:13.5px;white-space:nowrap}
.topnav a:hover{background:var(--bg2);color:var(--fg);text-decoration:none}
.topnav a.on{background:var(--bg2);color:var(--fg);border:1px solid var(--line2)}
.doc-shell{display:grid;grid-template-columns:288px minmax(0,1fr);align-items:start}
.doc-nav{
  position:sticky;top:59px;max-height:calc(100vh - 59px);overflow-y:auto;
  padding:16px 12px 70px;border-right:1px solid var(--line);
}
.doc-nav::-webkit-scrollbar{width:9px}
.doc-nav::-webkit-scrollbar-thumb{background:var(--line2);border-radius:9px}
.doc-nav a{display:block;padding:5px 10px;border-radius:8px;color:var(--dim);font-size:13px;line-height:1.4}
.doc-nav a:hover{background:var(--bg2);color:var(--fg);text-decoration:none}
.doc-nav a.lvl1{margin:14px 0 2px;font-weight:700;font-size:11.5px;letter-spacing:.07em;text-transform:uppercase;color:var(--fg)}
.doc-nav a.lvl2{padding-left:18px;border-left:1px solid var(--line);border-radius:0 8px 8px 0}
.doc-nav a.lvl3{padding-left:30px;font-size:12.4px;color:var(--dim2)}
.doc-nav a.lvl3:hover{color:var(--fg)}
.doc-nav a.active{color:var(--acc);background:color-mix(in srgb,var(--acc) 12%,transparent)}
.doc-search{
  width:100%;padding:9px 12px;border-radius:10px;border:1px solid var(--line2);
  background:var(--bg2);color:var(--fg);font-family:var(--sans);font-size:13px;outline:none;margin-bottom:4px;
}
.doc-search:focus{border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 18%,transparent)}
.doc-count{margin:18px 10px 0;font-size:11.5px;color:var(--dim2);font-family:var(--mono)}
.doc-main{padding:34px 46px 120px;max-width:1080px;min-width:0}
.doc-hero .eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--acc);margin-bottom:12px}
.doc-hero h1{font-size:clamp(30px,4.6vw,46px);line-height:1.04;letter-spacing:-.035em;margin:0 0 14px}
.doc-hero .lede{font-size:16.5px;color:var(--dim);max-width:72ch;margin:0 0 18px}
.doc-meta{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 20px}
.doc-meta span{
  font-family:var(--mono);font-size:11.5px;color:var(--dim);border:1px solid var(--line);
  border-radius:999px;padding:4px 11px;background:var(--panel);
}
.doc-actions{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start}
.doc-actions .ghost{flex:0 0 auto;width:auto}
.doc-body .topbar .icon-btn{margin-left:auto}
.ghost{
  display:inline-flex;align-items:center;gap:7px;background:var(--panel);border:1px solid var(--line2);
  color:var(--fg);border-radius:10px;padding:9px 14px;font-size:13.5px;font-family:var(--sans);cursor:pointer;
}
.ghost:hover{border-color:var(--acc);color:var(--acc);text-decoration:none}
.doc-content h1{
  font-size:clamp(24px,3vw,31px);letter-spacing:-.02em;margin:54px 0 10px;
  padding-top:26px;border-top:1px solid var(--line);
}
.doc-content .cs-group:first-child h1{margin-top:36px;padding-top:0;border-top:0}
.doc-content h1,.doc-content h2,.cs-sec{scroll-margin-top:72px}
.doc-content h2{font-size:19.5px;letter-spacing:-.01em;margin:30px 0 6px;color:var(--fg)}
.doc-content h3{font-size:15.2px;margin:22px 0 6px;color:var(--fg)}
.doc-content h3+ul,.doc-content h3+p{margin-top:4px}
.doc-content ul{margin:6px 0 12px}
.doc-content li>ul{margin:4px 0}
/* hashes and long paths must not widen the page on a phone */
.doc-content p,.doc-content li,.doc-content td{overflow-wrap:anywhere}
.doc-content p code{white-space:normal}
.doc-content table{display:block;width:100%;overflow-x:auto}
.cs-sec{padding-bottom:8px}
.cs-sec+.cs-sec{border-top:1px dashed var(--line);margin-top:6px}
.cs-sub{scroll-margin-top:70px}
.cs-sub+.cs-sub{margin-top:4px}
.doc-foot{margin-top:64px;padding-top:18px;border-top:1px solid var(--line);font-size:12.5px;color:var(--dim2)}
.doc-foot a{color:var(--dim)}
[hidden]{display:none!important}
@media (max-width:900px){
  .doc-shell{grid-template-columns:minmax(0,1fr)}
  .doc-nav{
    position:static;max-height:46vh;overflow-y:auto;-webkit-overflow-scrolling:touch;
    border-right:0;border-bottom:1px solid var(--line);
  }
  .doc-main{padding:26px 20px 90px}
  .topnav{display:none}
  .doc-body .topbar .icon-btn{flex:0 0 auto}
}
@media print{
  .topbar,.doc-nav,.doc-actions,#toast,.block-bar,.doc-foot{display:none!important}
  .doc-shell{display:block}
  .doc-main{padding:0;max-width:none}
  body{background:#fff;color:#000}
  .block,.block pre{background:#f6f8fa;color:#111;border-color:#ddd}
  .doc-content h1{page-break-after:avoid;border-top:0}
  .cs-sec{page-break-inside:auto}
  a{color:#000}
}
"""

CHEATSHEET_TEMPLATE = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSCP cheatsheet — every command on one page</title>
<meta name="description" content="OSCP cheatsheet: information gathering, web attacks, password attacks, Windows and Linux privilege escalation, pivoting, Metasploit, Active Directory. Every command with its flag.">
<meta property="og:type" content="article">
<meta property="og:title" content="OSCP cheatsheet — every command on one page">
<meta property="og:description" content="Every command from the lab work, grouped by phase, with copy buttons.">
<meta name="color-scheme" content="dark light">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>💀</text></svg>">
<style>%%CSS%%%%CHEATCSS%%</style>
</head>
<body class="doc-body">
<header class="topbar">
  <a class="brand" href="main.html" style="color:inherit;text-decoration:none"><span class="dot"></span>OSCP<span class="slash">/</span><span class="brand-sub">cheatsheet</span></a>
  <nav class="topnav">
    <a href="main.html">Labs</a>
    <a href="cheatsheet.html" class="on">Cheatsheet</a>
  </nav>
  <button class="icon-btn" id="themeBtn" type="button" aria-label="Toggle colour theme" title="Toggle theme">◐</button>
</header>

<div class="doc-shell">
  <aside class="doc-nav" aria-label="Contents">
    <input class="doc-search" id="csSearch" type="search" placeholder="Filter sections…" autocomplete="off" spellcheck="false" aria-label="Filter sections">
    <div class="nav-title">Contents</div>
%%TOC%%
    <p class="doc-count" id="csCount">%%META%%</p>
  </aside>

  <main class="doc-main">
    <div class="doc-hero">
      <div class="eyebrow">Reference</div>
      <h1>OSCP cheatsheet</h1>
      <p class="lede">
        Every command I reach for during an exam attempt, on one page: information gathering,
        web attacks, password attacks, Windows and Linux privilege escalation, pivoting,
        Metasploit and Active Directory. Commands are reproduced exactly as published; only
        the descriptions and inline comments are in English.
      </p>
      <div class="doc-meta">
        <span>%%SECS%% sections</span>
        <span>%%BLOCKS%% code blocks</span>
        <span>updated %%DATE%%</span>
      </div>
      <div class="doc-actions">
        <button class="ghost" id="copyAll" type="button">Copy every command</button>
        <a class="ghost" href="main.html">← Back to labs</a>
      </div>
    </div>

    <div class="content doc-content">
%%BODY%%
    </div>

    <footer class="doc-foot">
      <p>Command syntax is unchanged from the original; descriptions and inline comments were
        translated to English. Adapted from
        <a href="https://xn--ec6b17t.com/OSCP/OSCP-Cheatsheet" rel="noopener">KalioNix — OSCP Cheatsheet</a>.
        Lab-specific IPs, users and hashes are placeholders.</p>
    </footer>
  </main>
</div>

<div id="toast" role="status" aria-live="polite"></div>
<script>%%CHEATJS%%</script>
</body>
</html>
"""

CHEATSHEET_JS = r"""
(function(){
  "use strict";
  var root=document.documentElement;

  /* ---------- theme ---------- */
  var THEME_KEY="oscp-theme";
  function setTheme(t){root.setAttribute("data-theme",t);try{localStorage.setItem(THEME_KEY,t)}catch(e){}}
  var saved=null;try{saved=localStorage.getItem(THEME_KEY)}catch(e){}
  if(!saved&&window.matchMedia){saved=window.matchMedia("(prefers-color-scheme: light)").matches?"light":"dark";}
  setTheme(saved||"dark");
  var tb=document.getElementById("themeBtn");
  if(tb){tb.addEventListener("click",function(){setTheme(root.getAttribute("data-theme")==="dark"?"light":"dark");});}

  /* ---------- toast + clipboard ---------- */
  var toast=document.getElementById("toast"),timer=null;
  function say(msg){if(!toast)return;toast.textContent=msg;toast.classList.add("show");clearTimeout(timer);timer=setTimeout(function(){toast.classList.remove("show")},1600);}
  function fallback(text){
    var ta=document.createElement("textarea");ta.value=text;ta.style.position="fixed";ta.style.opacity="0";
    document.body.appendChild(ta);ta.select();try{document.execCommand("copy")}catch(e){}document.body.removeChild(ta);
  }
  function copy(text,btn){
    function ok(){if(btn){btn.classList.add("done");var t=btn.textContent;btn.textContent="Copied";
      setTimeout(function(){btn.classList.remove("done");btn.textContent=t},1400);}say("Copied to clipboard");}
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(ok).catch(function(){fallback(text);ok();});
    }else{fallback(text);ok();}
  }
  document.addEventListener("click",function(e){
    var btn=e.target.closest(".copy");
    if(!btn)return;
    var block=btn.closest(".block"),pre=block&&block.querySelector("pre");
    if(pre)copy(pre.innerText.replace(/\s+$/,""),btn);
  });
  var all=document.getElementById("copyAll");
  if(all){all.addEventListener("click",function(){
    var cmds=Array.prototype.map.call(document.querySelectorAll(".block pre"),function(p){return p.innerText.replace(/\s+$/,"")});
    if(!cmds.length){say("Nothing to copy");return;}
    copy(cmds.join("\n\n"),all);
  });}

  /* ---------- section filter ---------- */
  var q=document.getElementById("csSearch");
  var secs=Array.prototype.slice.call(document.querySelectorAll(".cs-sec"));
  var groups=Array.prototype.slice.call(document.querySelectorAll(".cs-group"));
  var subs=Array.prototype.slice.call(document.querySelectorAll(".cs-sub"));
  var links=Array.prototype.slice.call(document.querySelectorAll(".doc-nav a"));
  var count=document.getElementById("csCount");
  var baseCount=count?count.textContent:"";
  if(q){
    var apply=function(){
      var term=(q.value||"").toLowerCase().trim(),shown=0,vis={};
      subs.forEach(function(s){
        var hit=!term||s.textContent.toLowerCase().indexOf(term)!==-1;
        s.hidden=!hit;if(hit){vis[s.id]=1;}
      });
      secs.forEach(function(sec){
        var anySub=Array.prototype.some.call(sec.querySelectorAll(".cs-sub"),function(s){return !s.hidden;});
        var intro=(sec.getAttribute("data-intro")||"").toLowerCase();
        var hit=!term||anySub||intro.indexOf(term)!==-1;
        sec.hidden=!hit;if(hit){shown++;vis[sec.id]=1;}
      });
      groups.forEach(function(g){
        var any=Array.prototype.some.call(g.querySelectorAll(".cs-sec"),function(s){return !s.hidden;});
        g.hidden=!!term&&!any;
      });
      /* keep the toc hierarchy in step with the body: a visible target keeps its link,
         and a matched child keeps its parent groups visible */
      links.forEach(function(a){
        var id=(a.getAttribute("href")||"").slice(1);
        var direct=!term||(a.getAttribute("data-search")||"").toLowerCase().indexOf(term)!==-1;
        a.dataset.hit=(direct||vis[id])?"1":"0";
      });
      for(var i=links.length-1;i>=0;i--){
        var a=links[i];
        if(a.className==="lvl3"&&a.dataset.hit==="1"){
          for(var j=i-1;j>=0;j--){
            if(links[j].className==="lvl2"){links[j].dataset.hit="1";break;}
            if(links[j].className==="lvl1"){break;}
          }
        }
      }
      for(var k=links.length-1;k>=0;k--){
        var b=links[k];
        if(b.className==="lvl2"&&b.dataset.hit==="1"){
          for(var n=k-1;n>=0;n--){
            if(links[n].className==="lvl1"){links[n].dataset.hit="1";break;}
          }
        }
      }
      links.forEach(function(a){a.hidden=!!term&&a.dataset.hit!=="1";});
      if(count){count.textContent=term?(shown+" / "+baseCount):baseCount;}
    };
    q.addEventListener("input",apply);
    q.addEventListener("search",apply);
    document.addEventListener("keydown",function(e){
      var typing=/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if(e.key==="/"&&!typing){e.preventDefault();q.focus();}
      if(e.key==="Escape"&&document.activeElement===q){q.value="";apply();q.blur();}
    });
  }

  /* ---------- highlight the section in view ---------- */
  var heads=Array.prototype.slice.call(document.querySelectorAll(".doc-content h1[id],.doc-content h2[id],.cs-sub[id]"));
  if("IntersectionObserver" in window&&heads.length){
    var byId={};links.forEach(function(a){byId[a.getAttribute("href").slice(1)]=a;});
    var io=new IntersectionObserver(function(entries){
      entries.forEach(function(en){
        if(!en.isIntersecting)return;
        links.forEach(function(a){a.classList.remove("active");});
        var a=byId[en.target.id];
        if(a&&!a.hidden){a.classList.add("active");}
      });
    },{rootMargin:"-64px 0px -72% 0px",threshold:0});
    heads.forEach(function(h){io.observe(h);});
  }
})();
"""


def _slug(text: str, used: dict) -> str:
    """Stable anchor id, with -2/-3 suffixes for duplicate headings."""
    base = re.sub(r"[^a-z0-9]+", "-", html.unescape(text).lower()).strip("-") or "section"
    n = used.get(base, 0)
    used[base] = n + 1
    return base if n == 0 else f"{base}-{n + 1}"


def split_cheatsheet(src: str) -> list:
    """Split the markdown into H1 groups -> H2 sections -> H3 tool blocks.

    Fenced code is left untouched, so a '#' comment inside a command block can never start
    a new section.
    """
    groups: list = []
    group = None
    sec = None
    sub = None
    fence = False
    buf: list = []

    def new_group(title: str) -> dict:
        return {"title": title, "intro": "", "sections": []}

    def new_sec(title: str) -> dict:
        return {"title": title, "intro": "", "subs": []}

    def flush() -> None:
        text = "\n".join(buf).strip("\n")
        buf.clear()
        if not text.strip():
            return
        target = None
        if sub is not None:
            target = sub
            key = "md"
        elif sec is not None:
            target = sec
            key = "intro"
        elif group is not None:
            target = group
            key = "intro"
        if target is not None:
            target[key] += ("\n\n" if target[key] else "") + text + "\n"

    for line in src.splitlines():
        if line.startswith("```"):
            fence = not fence
        if not fence and line.startswith("# "):
            flush()
            group = new_group(line[2:].strip())
            groups.append(group)
            sec = sub = None
        elif not fence and line.startswith("## "):
            flush()
            if group is None:
                group = new_group("")
                groups.append(group)
            sec = new_sec(line[3:].strip())
            group["sections"].append(sec)
            sub = None
        elif not fence and line.startswith("### "):
            flush()
            if sec is None:
                if group is None:
                    group = new_group("")
                    groups.append(group)
                sec = new_sec("")
                group["sections"].append(sec)
            sub = {"title": line[4:].strip(), "md": ""}
            sec["subs"].append(sub)
        else:
            buf.append(line)
    flush()
    return groups


def render_doc(src: str) -> str:
    """Markdown -> HTML with the shared command/output card renderer."""
    blocks: list = []

    def stash(m):
        blocks.append((m.group(1).strip(), m.group(2)))
        return "\n\nCODEPLACEHOLDER%sZ\n\n" % (len(blocks) - 1)

    src = FENCE.sub(stash, src)
    out = markdown.Markdown(extensions=["tables", "attr_list", "sane_lists"]).convert(src)

    def unstash(m):
        lang, code = blocks[int(m.group(1))]
        # Pygments' console lexer swallows lines (hidden password input, trailing output),
        # which would silently drop commands from the page. Render transcripts verbatim.
        terminal = lang.lower() in {"console", "shell-session", "shellsession"}
        return code_block(code, lang, plain=terminal)

    return re.sub(r"<p>CODEPLACEHOLDER(\d+)Z</p>", unstash, out)


def build_cheatsheet() -> str:
    src = CHEATSHEET_MD.read_text(encoding="utf-8")
    groups = split_cheatsheet(src)
    used: dict = {}
    toc: list = []
    body: list = []
    sec_count = 0

    for group in groups:
        gid = _slug(group["title"], used)
        toc.append(f'<a class="lvl1" href="#{gid}">{html.escape(group["title"])}</a>')
        inner = []
        for sec in group["sections"]:
            sid = _slug(sec["title"], used)
            sec_count += 1
            toc.append(
                f'<a class="lvl2" href="#{sid}" '
                f'data-search="{html.escape(sec["title"].lower(), quote=True)}">'
                f'{html.escape(sec["title"])}</a>'
            )
            parts = []
            if sec["title"]:
                parts.append(f'<h2>{html.escape(sec["title"])}</h2>')
            parts.append(render_doc(sec["intro"]))
            for sub in sec["subs"]:
                bid = _slug(sub["title"], used)
                toc.append(
                    f'<a class="lvl3" href="#{bid}" '
                    f'data-search="{html.escape(sub["title"].lower(), quote=True)}">'
                    f'{html.escape(sub["title"])}</a>'
                )
                parts.append(
                    f'<div class="cs-sub" id="{bid}">'
                    f'<h3>{html.escape(sub["title"])}</h3>{render_doc(sub["md"])}</div>'
                )
            label = re.sub(r"\s+", " ", f'{sec["title"]} {sec["intro"]}'.lower()).strip()
            inner.append(
                f'<section class="cs-sec" id="{sid}" '
                f'data-intro="{html.escape(label, quote=True)}">{"".join(parts)}</section>'
            )
        head = f'<h1 id="{gid}">{html.escape(group["title"])}</h1>' if group["title"] else ""
        body.append(
            f'<section class="cs-group">{head}'
            f'{render_doc(group["intro"])}{"".join(inner)}</section>'
        )

    block_count = len(re.findall(r"^```", src, flags=re.M)) // 2
    meta = f"{sec_count} sections · {block_count} blocks"
    return (
        CHEATSHEET_TEMPLATE.replace("%%CSS%%", CSS)
        .replace("%%CHEATCSS%%", CHEATSHEET_CSS)
        .replace("%%CHEATJS%%", CHEATSHEET_JS)
        .replace("%%TOC%%", "\n".join(toc))
        .replace("%%BODY%%", "\n".join(body))
        .replace("%%SECS%%", str(sec_count))
        .replace("%%BLOCKS%%", str(block_count))
        .replace("%%META%%", meta)
        .replace("%%DATE%%", datetime.date.today().strftime("%d %B %Y"))
    )


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

    sheet = build_cheatsheet()
    CHEATSHEET_OUT.write_text(sheet, encoding="utf-8")
    print(f"wrote {CHEATSHEET_OUT.name} ({CHEATSHEET_OUT.stat().st_size/1024:.1f} KB, "
          f"{sheet.count(chr(10))} lines)")

    REDIRECT_OUT.write_text(REDIRECT_TEMPLATE, encoding="utf-8")
    print(f"wrote {REDIRECT_OUT.name} (redirect -> {HOME_OUT.name})")


if __name__ == "__main__":
    main()
