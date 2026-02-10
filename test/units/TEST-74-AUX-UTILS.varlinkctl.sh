#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

varlinkctl --help
varlinkctl help --no-pager
varlinkctl --version
varlinkctl --json=help

# TODO: abstract namespace sockets (@...)
# Path to a socket
varlinkctl info /run/systemd/journal/io.systemd.journal
varlinkctl info /run/systemd/../systemd/../../run/systemd/journal/io.systemd.journal
varlinkctl info "./$(realpath --relative-to="$PWD" /run/systemd/journal/io.systemd.journal)"
varlinkctl info unix:/run/systemd/journal/io.systemd.journal
varlinkctl info --json=off /run/systemd/journal/io.systemd.journal
varlinkctl info --json=pretty /run/systemd/journal/io.systemd.journal | jq .
varlinkctl info --json=short /run/systemd/journal/io.systemd.journal | jq .
varlinkctl info -j /run/systemd/journal/io.systemd.journal | jq .

varlinkctl list-interfaces /run/systemd/journal/io.systemd.journal
varlinkctl list-interfaces -j /run/systemd/journal/io.systemd.journal | jq .

varlinkctl list-methods /run/systemd/journal/io.systemd.journal
varlinkctl list-methods -j /run/systemd/journal/io.systemd.journal | jq .

varlinkctl list-methods /run/systemd/journal/io.systemd.journal io.systemd.Journal
varlinkctl list-methods -j /run/systemd/journal/io.systemd.journal io.systemd.Journal | jq .

varlinkctl introspect /run/systemd/journal/io.systemd.journal
varlinkctl introspect -j /run/systemd/journal/io.systemd.journal | jq --seq .

varlinkctl introspect /run/systemd/journal/io.systemd.journal io.systemd.Journal
varlinkctl introspect -j /run/systemd/journal/io.systemd.journal io.systemd.Journal | jq .

varlinkctl list-registry
varlinkctl list-registry -j | jq .
varlinkctl list-registry | grep io.systemd.Manager

if command -v userdbctl >/dev/null; then
    systemctl start systemd-userdbd
    varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "userName" : "testuser", "service" : "io.systemd.Multiplexer" }'
    varlinkctl call -q /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "userName" : "testuser", "service" : "io.systemd.Multiplexer" }'
    varlinkctl call -j /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "userName" : "testuser", "service" : "io.systemd.Multiplexer" }' | jq .
    # We ignore the return value of the following two calls, since if no memberships are defined at all this will return a NotFound error, which is OK
    varlinkctl call --more /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' --graceful=io.systemd.UserDatabase.NoRecordFound
    varlinkctl call --quiet --more /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' --graceful=io.systemd.UserDatabase.NoRecordFound
    varlinkctl call --more -j /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' --graceful=io.systemd.UserDatabase.NoRecordFound | jq --seq .
    varlinkctl call --oneway /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }'
    (! varlinkctl call --oneway /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' | grep .)
fi

IDL_FILE="$(mktemp)"
varlinkctl introspect /run/systemd/journal/io.systemd.journal io.systemd.Journal | tee "${IDL_FILE:?}"
varlinkctl validate-idl "$IDL_FILE"
cat /bin/sh >"$IDL_FILE"
(! varlinkctl validate-idl "$IDL_FILE")

if [[ -x /usr/lib/systemd/systemd-pcrextend ]]; then
    # Path to an executable
    varlinkctl info /usr/lib/systemd/systemd-pcrextend
    varlinkctl info exec:/usr/lib/systemd/systemd-pcrextend
    varlinkctl list-interfaces /usr/lib/systemd/systemd-pcrextend
    varlinkctl introspect /usr/lib/systemd/systemd-pcrextend io.systemd.PCRExtend
    varlinkctl introspect /usr/lib/systemd/systemd-pcrextend
fi

# Test various varlink socket units to make sure that we can still connect to the varlink sockets even if the
# services are currently stopped (or restarting).
systemctl stop \
    systemd-networkd.service \
    systemd-hostnamed.service \
    systemd-machined.service \
    systemd-udevd.service
varlinkctl introspect /run/systemd/netif/io.systemd.Network
varlinkctl introspect /run/systemd/io.systemd.Hostname
varlinkctl introspect /run/systemd/machine/io.systemd.Machine
if ! systemd-detect-virt -qc; then
    varlinkctl introspect /run/udev/io.systemd.Udev
fi

# SSH transport
SSHBINDIR="$(mktemp -d)"

rm_rf_sshbindir() {
    rm -rf "$SSHBINDIR"
}

trap rm_rf_sshbindir EXIT

# Create a fake "ssh" binary that validates everything works as expected if invoked for the "ssh-unix:" Varlink transport
cat > "$SSHBINDIR"/ssh <<'EOF'
#!/usr/bin/env bash

set -xe

test "$1" = "-W"
test "$2" = "/run/systemd/journal/io.systemd.journal"
test "$3" = "foobar"

exec socat - UNIX-CONNECT:/run/systemd/journal/io.systemd.journal
EOF
chmod +x "$SSHBINDIR"/ssh

SYSTEMD_SSH="$SSHBINDIR/ssh" varlinkctl info ssh-unix:foobar:/run/systemd/journal/io.systemd.journal

# Now build another fake "ssh" binary that does the same for "ssh-exec:"
cat > "$SSHBINDIR"/ssh <<'EOF'
#!/usr/bin/env bash

set -xe

test "$1" = "-e"
test "$2" = "none"
test "$3" = "-T"
test "$4" = "foobar"
test "$5" = "env"
test "$6" = "SYSTEMD_VARLINK_LISTEN=-"
test "$7" = "systemd-sysext"

SYSTEMD_VARLINK_LISTEN=- exec systemd-sysext
EOF
chmod +x "$SSHBINDIR"/ssh

SYSTEMD_SSH="$SSHBINDIR/ssh" varlinkctl info ssh-exec:foobar:systemd-sysext

# Go through all varlink sockets we can find under /run/systemd/ for some extra coverage
find /run/systemd/ -name "io.systemd*" -type s | while read -r socket; do
    varlinkctl info "$socket"
    varlinkctl info -j "$socket"
    varlinkctl list-interfaces "$socket"
    varlinkctl list-interfaces -j "$socket"
    varlinkctl list-methods "$socket"
    varlinkctl list-methods -j "$socket"
    varlinkctl introspect "$socket"
    varlinkctl introspect -j "$socket"

    varlinkctl list-interfaces "$socket" | while read -r interface; do
        varlinkctl introspect "$socket" "$interface"
    done

done

(! varlinkctl)
(! varlinkctl "")
(! varlinkctl info)
(! varlinkctl info "")
(! varlinkctl info /run/systemd/notify)
(! varlinkctl info /run/systemd/private)
# Relative paths must begin with ./
(! varlinkctl info "$(realpath --relative-to="$PWD" /run/systemd/journal/io.systemd.journal)")
(! varlinkctl info unix:)
(! varlinkctl info unix:"")
(! varlinkctl info exec:)
(! varlinkctl info exec:"")
(! varlinkctl list-interfaces)
(! varlinkctl list-interfaces "")
(! varlinkctl introspect)
(! varlinkctl introspect /run/systemd/journal/io.systemd.journal "")
(! varlinkctl introspect "" "")
(! varlinkctl list-methods /run/systemd/journal/io.systemd.journal "")
(! varlinkctl list-methods -j /run/systemd/journal/io.systemd.journal "")
(! varlinkctl list-methods "")
(! varlinkctl list-methods -j "")
(! varlinkctl call)
(! varlinkctl call "")
(! varlinkctl call "" "")
(! varlinkctl call "" "" "")
(! varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "service" : "io.systemd.ShouldNotExist" }')
(! varlinkctl validate-idl "")
(! varlinkctl validate-idl </dev/null)

varlinkctl info /run/systemd/io.systemd.Hostname
varlinkctl introspect /run/systemd/io.systemd.Hostname io.systemd.Hostname
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'

# Validate that --exec results in the very same values
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}' | jq >/tmp/describe1.json
varlinkctl --exec call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}' -- jq >/tmp/describe2.json
cmp /tmp/describe1.json /tmp/describe2.json
rm /tmp/describe1.json /tmp/describe2.json

# test io.systemd.Manager
varlinkctl info /run/systemd/io.systemd.Manager
varlinkctl introspect /run/systemd/io.systemd.Manager io.systemd.Manager
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Describe '{}'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Reload '{}'
# This will disconnect and fail, as the manager reexec and drops connections
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Manager.Reexecute '{}' ||:

# test io.systemd.Network
varlinkctl info /run/systemd/netif/io.systemd.Network
varlinkctl introspect /run/systemd/netif/io.systemd.Network io.systemd.Network
varlinkctl call /run/systemd/netif/io.systemd.Network io.systemd.Network.Describe '{}'

# test io.systemd.Unit
varlinkctl info /run/systemd/io.systemd.Manager
varlinkctl introspect /run/systemd/io.systemd.Manager io.systemd.Unit
varlinkctl --more call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "multi-user.target"}'
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"pid": {"pid": 1}}'
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{}' |& grep "called without 'more' flag" >/dev/null)
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "init.scope", "pid": {"pid": 1}}'
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": ""}')
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "non-existent.service"}')
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"pid": {"pid": -1}}' )
(! varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"name": "multi-user.target", "pid": {"pid": 1}}')
set +o pipefail
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties '{"runtime": true, "name": "non-existent.service", "properties": {"Markers": ["needs-restart"]}}' |& grep "io.systemd.Unit.NoSuchUnit"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.SetProperties '{"runtime": true, "name": "systemd-journald.service", "properties": {"LoadState": "foobar"}}' |& grep "io.systemd.Unit.PropertyNotSupported"
set -o pipefail

varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List '{"cgroup": "/init.scope"}'
invocation_id="$(systemctl show -P InvocationID systemd-journald.service)"
varlinkctl call /run/systemd/io.systemd.Manager io.systemd.Unit.List "{\"invocationID\": \"$invocation_id\"}"

# test io.systemd.Metrics
varlinkctl info /run/systemd/report/io.systemd.Manager

varlinkctl list-methods /run/systemd/report/io.systemd.Manager
varlinkctl list-methods -j /run/systemd/report/io.systemd.Manager io.systemd.Metrics | jq .

varlinkctl introspect /run/systemd/report/io.systemd.Manager
varlinkctl introspect -j /run/systemd/report/io.systemd.Manager io.systemd.Metrics | jq .

varlinkctl --more call /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Manager io.systemd.Metrics.Describe {}

# test io.systemd.Manager in user manager
testuser_uid=$(id -u testuser)
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl info "/run/user/$testuser_uid/systemd/io.systemd.Manager"
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl introspect "/run/user/$testuser_uid/systemd/io.systemd.Manager"
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl call "/run/user/$testuser_uid/systemd/io.systemd.Manager" io.systemd.Manager.Describe '{}'

# test io.systemd.Unit in user manager
systemd-run --wait --pipe --user --machine testuser@ \
        varlinkctl --more call "/run/user/$testuser_uid/systemd/io.systemd.Manager" io.systemd.Unit.List '{}'

# test report
systemd-report
