#!/usr/bin/python3 -I
# Start a semcode server and wait until it reports over the sd_notify protocol
# that its index is ready, then stop it. What systemd-notify --fork would do,
# except that it keeps the server's stdin open: a stdio server quits at end of
# input. The socket lives next to the wrapper, where the server's sandbox can
# see it. Exit status 0 when READY=1 arrives with a STATUS that says the index
# is up to date, 1 when the status reports a failure, the server exits, or it
# stays silent for thirty seconds.
import os, select, socket, subprocess, sys, tempfile, time

DEADLINE = 30.0
wrapper = sys.argv[1]
with tempfile.TemporaryDirectory(dir=os.path.dirname(wrapper)) as directory:
    path = os.path.join(directory, "notify")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    listener.bind(path)
    server = subprocess.Popen([wrapper], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, env={**os.environ, "NOTIFY_SOCKET": path})
    verdict = None
    until = time.monotonic() + DEADLINE
    while verdict is None and time.monotonic() < until and server.poll() is None:
        if not select.select([listener], [], [], 0.2)[0]:
            continue
        lines = listener.recv(4096).decode(errors="replace").splitlines()
        status = next((line[len("STATUS="):] for line in lines if line.startswith("STATUS=")), "")
        print(" ".join(lines), file=sys.stderr)
        if "READY=1" in lines:
            verdict = status.startswith("Index up to date")
        elif "failed" in status.lower():
            verdict = False
    try:
        server.stdin.close()
        server.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        server.kill()
    sys.exit(0 if verdict else 1)
