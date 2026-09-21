#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse
import json
import os
import socket
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer


def sd_notify(state: str) -> bool:
    notify_socket = os.environ.get('NOTIFY_SOCKET')
    if not notify_socket:
        return False
    if notify_socket.startswith('@'):
        notify_socket = '\0' + notify_socket[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(state.encode(), notify_socket)
    except OSError:
        return False
    return True


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)

        # Check optional attribute
        if auth := self.headers.get('Authorization'):
            print(f'Authorization: {auth}')

        # Validate JSON structure
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, 'Invalid JSON')
            return

        print(f"JSON: {s if len(s := str(data)) < 80 else s[:40] + '…' + s[-40:]}")

        if 'metrics' not in data:
            self.send_error(400, "Missing 'metrics' field")
            return

        response = json.dumps({'status': 'ok'}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        # Mimic the JSON answer of a freegeoip-style geolocation service, for
        # testing systemd-report-geoip. The address is deliberately not in
        # canonical form (and might not even be an address), to verify that
        # the client validates and normalizes it.
        if self.path != '/json/':
            self.send_error(404, 'Not Found')
            return

        response = json.dumps(
            {
                'ip': args.geoip_address,
                'country_code': 'DE',
                'country_name': 'Germany',
                'region_code': 'BE',
                'region_name': 'State of Berlin',
                'city': 'Berlin',
                'zip_code': '10785',
                'time_zone': 'Europe/Berlin',
                'latitude': 52.5061,
                'longitude': 13.3684,
                'metro_code': 0,
            }
        ).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, fmt, *args):
        print(f'{self.address_string()} - {fmt % args}')


parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=8089)
parser.add_argument('--cert', help='TLS certificate file')
parser.add_argument('--key', help='TLS private key file')
parser.add_argument(
    '--geoip-address',
    default='2001:0DB8:0000:0000:0000:0000:0000:0001',
    help='IP address to return in the geolocation answer',
)
args = parser.parse_args()

server = HTTPServer(('', args.port), Handler)
if args.cert and args.key:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f'Serving on https://localhost:{args.port}/')
else:
    print(f'Serving on http://localhost:{args.port}/')
try:
    sd_notify('READY=1')
    server.serve_forever()
except KeyboardInterrupt:
    print('\nStopped.')
