#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e
shopt -s nullglob

if [[ -n "$1" ]]; then
    generator=$1
elif [[ -x /usr/lib/systemd/system-generators/systemd-fstab-generator ]]; then
    generator=/usr/lib/systemd/system-generators/systemd-fstab-generator
elif [[ -x /lib/systemd/system-generators/systemd-fstab-generator ]]; then
    generator=/lib/systemd/system-generators/systemd-fstab-generator
else
    exit 1
fi

src="$(dirname "$0")/testdata/test-fstab-generator"

# fsck(8) is located in /usr/sbin on Debian
PATH=$PATH:/usr/sbin

for f in "$src"/test-*.input; do
    echo "*** Running $f"

    (
        out=$(mktemp --tmpdir --directory "test-fstab-generator.XXXXXXXXXX")
        # shellcheck disable=SC2064
        trap "rm -rf '$out'" EXIT INT QUIT PIPE

        exp="${f%.input}.expected"

        if [[ "${f##*/}" =~ \.fstab\.input ]]; then
            SYSTEMD_LOG_LEVEL=debug SYSTEMD_IN_INITRD=yes SYSTEMD_SYSFS_CHECK=no SYSTEMD_PROC_CMDLINE="fstab=yes root=fstab" SYSTEMD_FSTAB="$f" SYSTEMD_SYSROOT_FSTAB="/dev/null" $generator "$out" "$out" "$out"
        else
            SYSTEMD_LOG_LEVEL=debug SYSTEMD_IN_INITRD=yes SYSTEMD_PROC_CMDLINE="fstab=no $(cat "$f")" $generator "$out" "$out" "$out"
        fi

        if [[ -f "$out"/systemd-fsck-root.service ]]; then
            # For split-usr system
            sed -i -e 's:ExecStart=/lib/systemd/systemd-fsck:ExecStart=/usr/lib/systemd/systemd-fsck:' "$out"/systemd-fsck-root.service
        fi

        if [[ "${f##*/}" =~ \.fstab\.input ]]; then
            for i in "$out"/*.{mount,swap}; do
                sed -i -e 's:SourcePath=.*$:SourcePath=/etc/fstab:' "$i"
            done
        fi

        # We store empty files rather than symlinks, so that they don't get pruned when packaged up, so compare
        # the list of filenames rather than their content
        if ! diff -u <(find "$out" -printf '%P\n' | sort) <(find "$exp" -printf '%P\n' | sort); then
            echo "**** Unexpected output for $f"
            exit 1
        fi

        # Check the main units.
        if ! diff -u "$out" "$exp"; then
            echo "**** Unexpected output for $f"
            exit 1
        fi

        # Also check drop-ins.
        for i in "$out"/*; do
            [[ -d "$i" ]] || continue

            dir="${i##*/}"

            for j in "$i"/*; do
                fname="${j##*/}"
                expf="$exp/$dir/$fname"

                if [[ -L "$j" && ! -e "$j" ]]; then
                    # For dead symlink, we store an empty file.
                    if [[ ! -e "$expf" || -n "$(cat "$expf")" ]]; then
                        echo "**** Unexpected symlink $j created by $f"
                        exit 1
                    fi
                    continue
                fi

                if ! diff -u "$j" "$expf"; then
                    echo "**** Unexpected output in $j for $f"
                    exit 1
                fi
            done
        done
    ) || exit 1
done
