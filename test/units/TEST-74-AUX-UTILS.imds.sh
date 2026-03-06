#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh


if ! test -x /usr/lib/systemd/systemd-imdsd ; then
    echo "No imdsd installed, skipping test."
    exit 0
fi

at_exit() {
    set +e
    systemctl stop fake-imds systemd-imdsd.socket ||:
    ip link del dummy0 ||:
    rm -f /tmp/fake-imds.py /run/credstore/firstboot.hostname /run/credstore/acredtest /run/systemd/system/systemd-imdsd@.service.d/50-env.conf
}

trap at_exit EXIT

cat >/tmp/fake-imds.py <<EOF
#!/usr/bin/python3

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
EOF

chmod +x /tmp/fake-imds.py

systemd-run -p Type=notify --unit=fake-imds /tmp/fake-imds.py
systemctl status fake-imds

# Add a fake network interface so that IMDS gets going
ip link add dummy0 type dummy
ip addr add 192.168.47.11/24 dev dummy0

USERDATA='{"systemd.credentials":[{"name":"acredtest","text":"avalue"}]}'

# First try imdsd directly
IMDSD="/usr/lib/systemd/systemd-imdsd --vendor=test --data-url=http://192.168.47.11:8088 --well-known-key=userdata:/userdata --well-known-key=hostname:/hostname"
assert_eq "$($IMDSD --well-known=hostname)" "piff"
assert_eq "$($IMDSD --well-known=userdata)" "$USERDATA"
assert_eq "$($IMDSD /hostname)" "piff"
assert_eq "$($IMDSD /userdata)" "$USERDATA"

# Then, try it as Varlink service
mkdir -p /run/systemd/system/systemd-imdsd@.service.d/
cat >/run/systemd/system/systemd-imdsd@.service.d/50-env.conf <<EOF
[Service]
Environment=SYSTEMD_IMDS_VENDOR=test2
Environment=SYSTEMD_IMDS_DATA_URL=http://192.168.47.11:8088
Environment=SYSTEMD_IMDS_KEY_USERDATA=/userdata
Environment=SYSTEMD_IMDS_KEY_HOSTNAME=/hostname
EOF
systemctl daemon-reload
systemctl start systemd-imdsd.socket

assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=hostname)" "piff"
assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=userdata)" "$USERDATA"
assert_eq "$(/usr/lib/systemd/systemd-imds -u)" "$USERDATA"

/usr/lib/systemd/systemd-imds
/usr/lib/systemd/systemd-imds --import

assert_eq "$(cat /run/credstore/firstboot.hostname)" "piff"
assert_eq "$(cat /run/credstore/acredtest)" "avalue"
