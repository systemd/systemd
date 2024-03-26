#!/bin/sh
# Wrapper for running systemd-repart.
# systemd-repart has `--empty` to specify how to handle existing files.
# `--empty=create` will create a disk image if it doesn't exist
# and `--empty=force` will wipe the partitions
# but there isn't an option that will create a new disk image
# whether it previously existed or not
# so this wrapper script ensures it's removed before recreating.

systemd_repart=systemd-repart
output=""
while [ "$#" -gt 0 ]; do
    case "$1" in
    --systemd-repart)
        systemd_repart="$2"
	shift 2
	;;
    --)
        shift
	break
	;;
    *)
        output="$1"
	shift
	;;
    esac
done

if [ -z "$output" ]; then
    echo "No output path provided" >&2
    exit 1
fi

rm -f "$output"
exec "$systemd_repart" --empty=create "$@" "$output"
