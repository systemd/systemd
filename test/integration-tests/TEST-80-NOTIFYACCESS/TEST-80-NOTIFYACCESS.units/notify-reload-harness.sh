#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

MODE="${1:-well-behaved}"
FIFO_IN="${2:-/tmp/reload-test-fifo-in}"
FIFO_OUT="${3:-/tmp/reload-test-fifo-out}"

handle_signal() {
    echo "reload" >"$FIFO_OUT"
    systemd-notify --reloading
    systemd-notify --ready --status="Reloaded"
}

case "$MODE" in
    no-handler)
        ;;
    toggle-handler|well-behaved)
        trap 'handle_signal' HUP
        ;;
    *)
        echo "Unknown mode: $MODE" >&2
        exit 1
        ;;
esac

systemd-notify --ready --status="Started with mode=$MODE"

while read -r cmd < "$FIFO_IN"; do
    case "$cmd" in
        remove-handler)
            trap - HUP
            echo "handler-removed" >"$FIFO_OUT"
            ;;
        exit)
            break
            ;;
        *)
            echo "Unknown command: $cmd" >&2
            exit 1
            ;;
    esac
done
