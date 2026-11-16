#!/usr/bin/env python3
"""Minimal raw HTTP capture server: logs each request line + time to a file."""
import datetime
import socketserver
import sys

LOG = "/tmp/t4s/callback_capture.log"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline().decode("latin-1").strip()
        headers = []
        while True:
            h = self.rfile.readline().decode("latin-1").strip()
            if not h:
                break
            headers.append(h)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG, "a") as fh:
            fh.write(f"[{ts}] {self.client_address[0]}:{self.client_address[1]} {line}\n")
            for h in headers:
                fh.write(f"[{ts}]   {h}\n")
        body = b"ok\n"
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
        self.wfile.write(body)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    with Server(("0.0.0.0", port), Handler) as srv:
        print(f"capture server on {port}", flush=True)
        srv.serve_forever()
