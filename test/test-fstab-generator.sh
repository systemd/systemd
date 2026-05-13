#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
shopt -s nullglob
shopt -s globstar

if [[ -n "${1:-}" ]]; then
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

test_one() (
    local initrd input out exp i j k dir fname expf

    input=${1?}
    initrd=${2?}

    : "*** Running $input (initrd=$initrd)"

    out=$(mktemp --tmpdir --directory "test-fstab-generator.XXXXXXXXXX")
    # shellcheck disable=SC2064
    trap "rm -rf '$out'" EXIT INT QUIT PIPE

    exp="${input%.input}.expected"
    if [[ "${input##*/}" =~ swap ]] && systemd-detect-virt --container >/dev/null; then
        exp="${exp}.container"
    fi
    if [[ "$initrd" == no ]]; then
        exp="${exp}.sysroot"
    fi

    if [[ "${input##*/}" =~ \.fstab\.input ]]; then
        SYSTEMD_LOG_LEVEL=debug SYSTEMD_IN_INITRD="$initrd" SYSTEMD_SYSFS_CHECK=no SYSTEMD_PROC_CMDLINE="fstab=yes root=fstab" SYSTEMD_FSTAB="$input" SYSTEMD_SYSROOT_FSTAB="/dev/null" "$generator" "$out" "$out" "$out"
    else
        SYSTEMD_LOG_LEVEL=debug SYSTEMD_IN_INITRD="$initrd" SYSTEMD_SYSFS_CHECK=no SYSTEMD_PROC_CMDLINE="fstab=no $(cat "$input")" "$generator" "$out" "$out" "$out"
    fi

    # The option x-systemd.growfs creates symlink to system's systemd-growfs@.service in .mount.wants directory.
    # Also, when $initrd is no, symlink to systemd-remount-fs.service is created.
    # The system that the test is currently running on may not have or may have outdated unit file.
    # Let's replace the symlink with an empty file.
    for i in "$out"/*/systemd-growfs@*.service "$out"/local-fs.target.wants/systemd-remount-fs.service; do
        [[ -L "$i" ]] || continue
        rm "$i"
        touch "$i"
    done

    if [[ "${input##*/}" =~ \.fstab\.input ]]; then
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

    # We do not store empty directory.
    if [[ -z "$(ls -A "$out")" && ! -d "$exp" ]]; then
        return 0
    fi

    # We store empty files rather than dead symlinks, so that they don't get pruned when packaged up, so compare
    # the list of filenames rather than their content
    if ! diff -u <(find "$out" -printf '%P\n' | sort) <(find "$exp" -printf '%P\n' | sort); then
        : "**** Unexpected output for $input (initrd=$initrd)"
        return 1
    fi

    # Check the main units.
    if ! diff -u "$out" "$exp"; then
        : "**** Unexpected output for $input (initrd=$initrd)"
        return 1
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
                    : "**** Unexpected symlink $j created by $input (initrd=$initrd)"
                    return 1
                fi
                continue
            fi

            if ! diff -u "$j" "$expf"; then
                : "**** Unexpected output in $j for $input (initrd=$initrd)"
                return 1
            fi
        done
    done

    return 0
)

for f in "$src"/test-*.input; do
    # If /mnt is a symlink, then the expected output from this
    # test scenario will not match the actual output
    if test "$f" = "$src/test-18-options.fstab.input" -a "$(readlink /mnt)" != "/mnt"
    then
        echo "Skip $f because /mnt is a symlink"
        continue
    fi

    test_one "$f" yes
    test_one "$f" no
done
