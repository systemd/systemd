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

varlinkctl introspect /run/systemd/journal/io.systemd.journal io.systemd.Journal
varlinkctl introspect -j /run/systemd/journal/io.systemd.journal io.systemd.Journal | jq .

if command -v userdbctl >/dev/null; then
    systemctl start systemd-userdbd
    varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "userName" : "testuser", "service" : "io.systemd.Multiplexer" }'
    varlinkctl call -j /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord '{ "userName" : "testuser", "service" : "io.systemd.Multiplexer" }' | jq .
    varlinkctl call --more /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }'
    varlinkctl call --more -j /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' | jq --seq .
    varlinkctl call --oneway /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }'
    (! varlinkctl call --oneway /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetMemberships '{ "service" : "io.systemd.Multiplexer" }' | grep .)
fi

IDL_FILE="$(mktemp)"
varlinkctl introspect /run/systemd/journal/io.systemd.journal io.systemd.Journal | tee "${IDL_FILE:?}"
varlinkctl validate-idl "$IDL_FILE"
varlinkctl validate-idl "$IDL_FILE"
cat /bin/sh >"$IDL_FILE"
(! varlinkctl validate-idl "$IDL_FILE")

if [[ -x /usr/lib/systemd/systemd-pcrextend ]]; then
    # Path to an executable
    varlinkctl info /usr/lib/systemd/systemd-pcrextend
    varlinkctl info exec:/usr/lib/systemd/systemd-pcrextend
    varlinkctl list-interfaces /usr/lib/systemd/systemd-pcrextend
    varlinkctl introspect /usr/lib/systemd/systemd-pcrextend io.systemd.PCRExtend
fi

# Go through all varlink sockets we can find under /run/systemd/ for some extra coverage
find /run/systemd/ -name "io.systemd*" -type s | while read -r socket; do
    varlinkctl info "$socket"

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
(! varlinkctl introspect /run/systemd/journal/io.systemd.journal)
(! varlinkctl introspect /run/systemd/journal/io.systemd.journal "")
(! varlinkctl introspect "" "")
(! varlinkctl call)
(! varlinkctl call "")
(! varlinkctl call "" "")
(! varlinkctl call "" "" "")
(! varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer io.systemd.UserDatabase.GetUserRecord </dev/null)
(! varlinkctl validate-idl "")
(! varlinkctl validate-idl </dev/null)

varlinkctl info /run/systemd/io.systemd.Hostname
varlinkctl introspect /run/systemd/io.systemd.Hostname io.systemd.Hostname
varlinkctl call /run/systemd/io.systemd.Hostname io.systemd.Hostname.Describe '{}'
