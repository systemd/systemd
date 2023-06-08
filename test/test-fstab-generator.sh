#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e
shopt -s nullglob
shopt -s globstar

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

# systemd-pcrfs@.service could be enabled or not, depending on the host state
# of the host system. Override the measurement to avoid the issue.
export SYSTEMD_FORCE_MEASURE=0

for f in "$src"/test-*.input; do
    echo "*** Running $f"

    (
        out=$(mktemp --tmpdir --directory "test-fstab-generator.XXXXXXXXXX")
        # shellcheck disable=SC2064
        trap "rm -rf '$out'" EXIT INT QUIT PIPE

        exp="${f%.input}.expected"
        if [[ "${f##*/}" =~ swap ]] && systemd-detect-virt --container >/dev/null; then
            exp="${exp}.container"
        fi

        if [[ "${f##*/}" =~ \.fstab\.input ]]; then
            SYSTEMD_LOG_LEVEL=debug SYSTEMD_IN_INITRD=yes SYSTEMD_SYSFS_CHECK=no SYSTEMD_PROC_CMDLINE="fstab=yes root=fstab" SYSTEMD_FSTAB="$f" SYSTEMD_SYSROOT_FSTAB="/dev/null" $generator "$out" "$out" "$out"
        else
            SYSTEMD_LOG_LEVEL=debug SYSTEMD_IN_INITRD=yes SYSTEMD_SYSFS_CHECK=no SYSTEMD_PROC_CMDLINE="fstab=no $(cat "$f")" $generator "$out" "$out" "$out"
        fi

        # The option x-systemd.growfs creates symlink to system's systemd-growfs@.service in .mount.wants directory.
        # The system that the test is currently running on may not have or may have outdated unit file.
        # Let's replace the symlink with an empty file.
        for i in "$out"/*/systemd-growfs@*.service; do
            [[ -L "$i" ]] || continue
            rm "$i"
            touch "$i"
        done

        # For split-usr system
        for i in "$out"/systemd-*.service; do
            sed -i -e 's:ExecStart=/lib/systemd/:ExecStart=/usr/lib/systemd/:' "$i"
        done

        if [[ "${f##*/}" =~ \.fstab\.input ]]; then
            for i in "$out"/*.{automount,mount,swap}; do
                sed -i -e 's:SourcePath=.*$:SourcePath=/etc/fstab:' "$i"
            done
        fi

        # .deb packager seems to dislike files named with backslash. So, as a workaround, we store files
        # without backslash in .expected.
        for i in "$out"/**/*\\*.{mount,swap}; do
            k="${i//\\/}"
            if [[ "$i" != "$k" ]]; then
                if [[ -f "$i" ]]; then
                    mv "$i" "$k"
                elif [[ -L "$i" ]]; then
                    dest=$(readlink "$i")
                    rm "$i"
                    ln -s "${dest//\\/}" "$k"
                fi
            fi
        done

        # We store empty files rather than dead symlinks, so that they don't get pruned when packaged up, so compare
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
