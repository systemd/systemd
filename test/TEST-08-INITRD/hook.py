#!/usr/bin/python3

import re

def check_result(mountpoint, console_log):
    if (mountpoint / "skipped").exists():
        return

    saw_hello = False
    for line in console_log:
        if (re.match(br"systemd-shutdown.+: Failed to move /run/initramfs", line)
            or re.match(br"systemd-shutdown.+: Failed to switch root", line)):

            raise Exception("sd-shutdown failed to switch root in shutdown initrd")

        if re.match(br"^Hello from shutdown initrd\s*$", line):
            saw_hello = True

    if not saw_hello:
        raise Exception("Missing 'hello' message from shutdown initrd")
