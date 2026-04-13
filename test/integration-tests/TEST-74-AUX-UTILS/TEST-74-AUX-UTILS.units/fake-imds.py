#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os, socket
from http.server import BaseHTTPRequestHandler, HTTPServer

def sd_notify(state: str) -> bool:
    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return False
    if notify_socket.startswith("@"):
        notify_socket = "\0" + notify_socket[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(state.encode(), notify_socket)
    except OSError:
        return False

    return True

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/userdata":
            body = b"{\"systemd.credentials\":[{\"name\":\"acredtest\",\"text\":\"avalue\"}]}"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/hostname":
            body = b"piff"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")

PORT=8088

server = HTTPServer(("", PORT), Handler)
print(f"Serving on http://localhost:{PORT}/")
try:
    sd_notify("READY=1")
    server.serve_forever()
except KeyboardInterrupt:
    print("\nStopped.")
