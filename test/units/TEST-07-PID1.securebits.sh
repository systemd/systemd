#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# SecureBits= in system.conf is set on PID 1 and inherited by every service.
# Locked bits cannot be cleared again, so exec-restrict-file stays locked for
# the rest of the boot. Nothing in the image reacts to it.

if ! command -v python3 >/dev/null; then
    echo "python3 not available, skipping" >&2
    exit 77
fi

# The exec-* bits exist since Linux 6.14, older kernels refuse them.
if ! systemd-run --wait --quiet -p SecureBits=exec-restrict-file true; then
    echo "kernel does not support the exec-restrict-file secure bit, skipping" >&2
    exit 77
fi

# Secure bits of a service started by PID 1, as a number.
service_securebits() {
    systemd-run --wait --pipe --quiet "$@" python3 -c \
        'import ctypes; print(ctypes.CDLL(None, use_errno=True).prctl(27, 0, 0, 0, 0))'
}

set_manager_securebits() {
    mkdir -p /run/systemd/system.conf.d
    printf '[Manager]\nSecureBits=%s\n' "$1" >/run/systemd/system.conf.d/99-securebits.conf
    systemctl daemon-reexec
}

at_exit() {
    set +e
    # Clear what isn't locked, then leave the configuration as we found it.
    set_manager_securebits ""
    rm -f /run/systemd/system.conf.d/99-securebits.conf
    systemctl daemon-reexec
}

RESTRICT_FILE=$((1 << 8))
RESTRICT_FILE_LOCKED=$((1 << 9))
DENY_INTERACTIVE=$((1 << 10))

if [[ $(service_securebits) -ne 0 ]]; then
    echo "secure bits already set, skipping" >&2
    exit 77
fi

trap at_exit EXIT

# A service that sets none itself inherits them.
set_manager_securebits "exec-restrict-file exec-restrict-file-locked"
[[ $(service_securebits) -eq $((RESTRICT_FILE | RESTRICT_FILE_LOCKED)) ]]

# A unit's own SecureBits= adds to the locked bits instead of failing to clear them.
[[ $(service_securebits -p SecureBits=exec-deny-interactive) -eq $((RESTRICT_FILE | RESTRICT_FILE_LOCKED | DENY_INTERACTIVE)) ]]

# A configuration change applies on reexec, locked bits stay.
set_manager_securebits "exec-deny-interactive"
[[ $(service_securebits) -eq $((RESTRICT_FILE | RESTRICT_FILE_LOCKED | DENY_INTERACTIVE)) ]]

# An empty assignment clears what isn't locked.
set_manager_securebits ""
[[ $(service_securebits) -eq $((RESTRICT_FILE | RESTRICT_FILE_LOCKED)) ]]
