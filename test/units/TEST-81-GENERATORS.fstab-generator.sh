#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235,SC2233
set -eux
set -o pipefail

# shellcheck source=test/units/generator-utils.sh
. "$(dirname "$0")/generator-utils.sh"

GENERATOR_BIN="/usr/lib/systemd/system-generators/systemd-fstab-generator"
NETWORK_FS_RX="^(afs|ceph|cifs|gfs|gfs2|ncp|ncpfs|nfs|nfs4|ocfs2|orangefs|pvfs2|smb3|smbfs|davfs|glusterfs|lustre|sshfs)$"
OUT_DIR="$(mktemp -d /tmp/fstab-generator.XXX)"
FSTAB="$(mktemp)"

at_exit() {
    mountpoint -q /proc/cmdline && umount /proc/cmdline
    rm -fr "${OUT_DIR:?}" "${FSTAB:?}"
}

trap at_exit EXIT

test -x "${GENERATOR_BIN:?}"

FSTAB_GENERAL=(
    # Valid entries
    "/dev/test2     /nofail                             ext4        nofail 0 0"
    "/dev/test3     /regular                            btrfs       defaults 0 0"
    "/dev/test4     /x-systemd.requires                 xfs         x-systemd.requires=foo.service 0 0"
    "/dev/test5     /x-systemd.before-after             xfs         x-systemd.before=foo.service,x-systemd.after=bar.mount 0 0"
    "/dev/test6     /x-systemd.wanted-required-by       xfs         x-systemd.wanted-by=foo.service,x-systemd.required-by=bar.device 0 0"
    "/dev/test7     /x-systemd.requires-mounts-for      xfs         x-systemd.requires-mounts-for=/foo/bar/baz 0 0"
    "/dev/test8     /x-systemd.automount-idle-timeout   vfat        x-systemd.automount,x-systemd.idle-timeout=50s 0 0"
    "/dev/test9     /x-systemd.makefs                   xfs         x-systemd.makefs 0 0"
    "/dev/test10    /x-systemd.growfs                   xfs         x-systemd.growfs 0 0"
    "/dev/test11    /_netdev                            ext4        defaults,_netdev 0 0"
    "/dev/test12    /_rwonly                            ext4        x-systemd.rw-only 0 0"
    "/dev/test13    /chaos1                             zfs         x-systemd.rw-only,x-systemd.requires=hello.service,x-systemd.after=my.device 0 0"
    "/dev/test14    /chaos2                             zfs         x.systemd.wanted-by=foo.service,x-systemd.growfs,x-systemd.makefs 0 0"
    "/dev/test15    /fstype/auto                        auto        defaults 0 0"
    "/dev/test16    /fsck/me                            ext4        defaults 0 1"
    "/dev/test17    /also/fsck/me                       ext4        defaults,x-systemd.requires-mounts-for=/var/lib/foo 0 99"
    "/dev/test18    /swap                               swap        defaults 0 0"
    "/dev/test19    /swap/makefs                        swap        defaults,x-systemd.makefs 0 0"
    "/dev/test20    /var                                xfs         defaults,x-systemd.device-timeout=1h 0 0"
    "/dev/test21    /usr                                ext4        defaults 0 1"
    "/dev/test22    /initrd/mount                       ext2        defaults,x-systemd.rw-only,x-initrd.mount 0 1"
    "/dev/test23    /initrd/mount/nofail                ext3        defaults,nofail,x-initrd.mount 0 1"
    "/dev/test24    /initrd/mount/deps                  ext4        x-initrd.mount,x-systemd.before=early.service,x-systemd.after=late.service 0 1"

    # Incomplete, but valid entries
    "/dev/incomplete1 /incomplete1"
    "/dev/incomplete2 /incomplete2                      ext4"
    "/dev/incomplete3 /incomplete3                      ext4        defaults"
    "/dev/incomplete4 /incomplete4                      ext4        defaults 0"

    # Remote filesystems
    "/dev/remote1   /nfs                                nfs         bg 0 0"
    "/dev/remote2   /nfs4                               nfs4        bg 0 0"
    "bar.tld:/store /remote/storage                     nfs         ro,x-systemd.wanted-by=store.service 0 0"
    "user@host.tld:/remote/dir /remote/top-secret       sshfs       rw,x-systemd.before=naughty.service 0 0"
    "foo.tld:/hello /hello/world                        ceph        defaults 0 0"
    "//192.168.0.1/storage /cifs-storage                cifs        automount,nofail 0 0"
)

FSTAB_GENERAL_ROOT=(
    # rootfs with bunch of options we should ignore and fsck enabled
    "/dev/test1     /                                   ext4        noauto,nofail,x-systemd.automount,x-systemd.wanted-by=foo,x-systemd.required-by=bar 0 1"
    "${FSTAB_GENERAL[@]}"
)

FSTAB_MINIMAL=(
    "/dev/loop1     /foo/bar                            ext3        defaults 0 0"
)

FSTAB_DUPLICATE=(
    "/dev/dup1     /       ext4 defaults 0 1"
    "/dev/dup2     /       ext4 defaults,x-systemd.requires=foo.mount 0 2"
)

FSTAB_INVALID=(
    # Ignored entries
    "/dev/ignored1  /sys/fs/cgroup/foo                  ext4        defaults    0 0"
    "/dev/ignored2  /sys/fs/selinux                     ext4        defaults    0 0"
    "/dev/ignored3  /dev/console                        ext4        defaults    0 0"
    "/dev/ignored4  /proc/kmsg                          ext4        defaults    0 0"
    "/dev/ignored5  /proc/sys                           ext4        defaults    0 0"
    "/dev/ignored6  /proc/sys/kernel/random/boot_id     ext4        defaults    0 0"
    "/dev/ignored7  /run/host                           ext4        defaults    0 0"
    "/dev/ignored8  /run/host/foo                       ext4        defaults    0 0"
    "/dev/ignored9  /autofs                             autofs      defaults    0 0"
    "/dev/invalid1  not-a-path                          ext4        defaults    0 0"
    ""
    "/dev/invalid1"
    "			"
    "\\"
    "$"
)

check_fstab_mount_units() {
    local what where fstype opts passno unit
    local item opt split_options filtered_options supp service device arg
    local array_name="${1:?}"
    local out_dir="${2:?}/normal"
    # Get a reference to the array from its name
    local -n fstab_entries="$array_name"

    # Running the checks in a container is pretty much useless, since we don't
    # generate any mounts, but don't skip the whole test to test the "skip"
    # paths as well
    in_container && return 0

    for item in "${fstab_entries[@]}"; do
        # Don't use a pipe here, as it would make the variables out of scope
        read -r what where fstype opts _ passno <<< "$item"

        # Skip non-initrd mounts in initrd
        if in_initrd_host && ! [[ "$opts" =~ x-initrd.mount ]]; then
            continue
        fi

        if [[ "$fstype" == swap ]]; then
            unit="$(systemd-escape --suffix=swap --path "${what:?}")"
            cat "$out_dir/$unit"

            grep -qE "^What=$what$" "$out_dir/$unit"
            if [[ "$opts" != defaults ]]; then
                grep -qE "^Options=$opts$" "$out_dir/$unit"
            fi

            if [[ "$opts" =~ x-systemd.makefs ]]; then
                service="$(systemd-escape --template=systemd-mkswap@.service --path "$what")"
                test -e "$out_dir/$service"
            fi

            continue
        fi

        # If we're parsing host's fstab in initrd, prefix all mount targets
        # with /sysroot
        in_initrd_host && where="/sysroot${where:?}"
        unit="$(systemd-escape --suffix=mount --path "${where:?}")"
        cat "$out_dir/$unit"

        # Check the general stuff
        grep -qE "^What=$what$" "$out_dir/$unit"
        grep -qE "^Where=$where$" "$out_dir/$unit"
        if [[ -n "$fstype" ]] && [[ "$fstype" != auto ]]; then
            grep -qE "^Type=$fstype$" "$out_dir/$unit"
        fi
        if [[ -n "$opts" ]] && [[ "$opts" != defaults ]]; then
            # Some options are not propagated to the generated unit
            if [[ "$where" == / || "$where" == /usr ]]; then
                filtered_options="$(opt_filter "$opts" "(noauto|nofail|x-systemd.(wanted-by=|required-by=|automount|device-timeout=))")"
            else
                filtered_options="$(opt_filter "$opts" "^x-systemd.device-timeout=")"
            fi

            if [[ "${filtered_options[*]}" != defaults ]]; then
                grep -qE "^Options=.*$filtered_options.*$" "$out_dir/$unit"
            fi
        fi

        if ! [[ "$opts" =~ (noauto|x-systemd.(wanted-by=|required-by=|automount)) ]]; then
            # We don't create the Requires=/Wants= symlinks for noauto/automount mounts
            # and for mounts that use x-systemd.wanted-by=/required-by=
            if in_initrd_host; then
                if [[ "$where" == / ]] || ! [[ "$opts" =~ nofail ]]; then
                    link_eq "$out_dir/initrd-fs.target.requires/$unit" "../$unit"
                else
                    link_eq "$out_dir/initrd-fs.target.wants/$unit" "../$unit"
                fi
            elif [[ "$fstype" =~ $NETWORK_FS_RX || "$opts" =~ _netdev ]]; then
                # Units with network filesystems should have a Requires= dependency
                # on the remote-fs.target, unless they use nofail or are an nfs "bg"
                # mounts, in which case the dependency is downgraded to Wants=
                if [[ "$opts" =~ nofail ]] || [[ "$fstype" =~ ^(nfs|nfs4) && "$opts" =~ bg ]]; then
                    link_eq "$out_dir/remote-fs.target.wants/$unit" "../$unit"
                else
                    link_eq "$out_dir/remote-fs.target.requires/$unit" "../$unit"
                fi
            else
                # Similarly, local filesystems should have a Requires= dependency on
                # the local-fs.target, unless they use nofail, in which case the
                # dependency is downgraded to Wants=. Rootfs is a special case,
                # since we always ignore nofail there
                if [[ "$where" == / ]] || ! [[ "$opts" =~ nofail ]]; then
                    link_eq "$out_dir/local-fs.target.requires/$unit" "../$unit"
                else
                    link_eq "$out_dir/local-fs.target.wants/$unit" "../$unit"
                fi
            fi
        fi

        if [[ "${passno:=0}" -ne 0 ]]; then
            # Generate systemd-fsck@.service dependencies, if applicable
            if in_initrd && [[ "$where" == / || "$where" == /usr ]]; then
                continue
            fi

            if [[ "$where" == / ]]; then
                link_endswith "$out_dir/local-fs.target.wants/systemd-fsck-root.service" "/lib/systemd/system/systemd-fsck-root.service"
            else
                service="$(systemd-escape --template=systemd-fsck@.service --path "$what")"
                grep -qE "^After=$service$" "$out_dir/$unit"
                if [[ "$where" == /usr ]]; then
                    grep -qE "^Wants=$service$" "$out_dir/$unit"
                else
                    grep -qE "^Requires=$service$" "$out_dir/$unit"
                fi
            fi
        fi

        # Check various x-systemd options
        #
        # First, split them into an array to make splitting them even further
        # easier
        IFS="," read -ra split_options <<< "$opts"
        # and process them one by one.
        #
        # Note: the "machinery" below might (and probably does) miss some
        #       combinations of supported options, so tread carefully
        for opt in "${split_options[@]}"; do
            if [[ "$opt" =~ ^x-systemd.requires= ]]; then
                service="$(opt_get_arg "$opt")"
                grep -qE "^Requires=$service$" "$out_dir/$unit"
                grep -qE "^After=$service$" "$out_dir/$unit"
            elif [[ "$opt" =~ ^x-systemd.before= ]]; then
                service="$(opt_get_arg "$opt")"
                grep -qE "^Before=$service$" "$out_dir/$unit"
            elif [[ "$opt" =~ ^x-systemd.after= ]]; then
                service="$(opt_get_arg "$opt")"
                grep -qE "^After=$service$" "$out_dir/$unit"
            elif [[ "$opt" =~ ^x-systemd.wanted-by= ]]; then
                service="$(opt_get_arg "$opt")"
                if [[ "$where" == / ]]; then
                    # This option is ignored for rootfs mounts
                    (! link_eq "$out_dir/$service.wants/$unit" "../$unit")
                else
                    link_eq "$out_dir/$service.wants/$unit" "../$unit"
                fi
            elif [[ "$opt" =~ ^x-systemd.required-by= ]]; then
                service="$(opt_get_arg "$opt")"
                if [[ "$where" == / ]]; then
                    # This option is ignored for rootfs mounts
                    (! link_eq "$out_dir/$service.requires/$unit" "../$unit")
                else
                    link_eq "$out_dir/$service.requires/$unit" "../$unit"
                fi
            elif [[ "$opt" =~ ^x-systemd.requires-mounts-for= ]]; then
                arg="$(opt_get_arg "$opt")"
                grep -qE "^RequiresMountsFor=$arg$" "$out_dir/$unit"
            elif [[ "$opt" == x-systemd.device-bound ]]; then
                # This is implied for fstab mounts
                :
            elif [[ "$opt" == x-systemd.automount ]]; then
                # The $unit should have an accompanying automount unit
                supp="$(systemd-escape --suffix=automount --path "$where")"
                if [[ "$where" == / ]]; then
                    # This option is ignored for rootfs mounts
                    test ! -e "$out_dir/$supp"
                    (! link_eq "$out_dir/local-fs.target.requires/$supp" "../$supp")
                else
                    test -e "$out_dir/$supp"
                    link_eq "$out_dir/local-fs.target.requires/$supp" "../$supp"
                fi
            elif [[ "$opt" =~ ^x-systemd.idle-timeout= ]]; then
                # The timeout applies to the automount unit, not the original
                # mount one
                arg="$(opt_get_arg "$opt")"
                supp="$(systemd-escape --suffix=automount --path "$where")"
                grep -qE "^TimeoutIdleSec=$arg$" "$out_dir/$supp"
            elif [[ "$opt" =~ ^x-systemd.device-timeout= ]]; then
                arg="$(opt_get_arg "$opt")"
                device="$(systemd-escape --suffix=device --path "$what")"
                grep -qE "^JobRunningTimeoutSec=$arg$" "$out_dir/${device}.d/50-device-timeout.conf"
            elif [[ "$opt" == x-systemd.makefs ]]; then
                service="$(systemd-escape --template=systemd-makefs@.service --path "$what")"
                test -e "$out_dir/$service"
                link_eq "$out_dir/${unit}.requires/$service" "../$service"
            elif [[ "$opt" == x-systemd.rw-only ]]; then
                grep -qE "^ReadWriteOnly=yes$" "$out_dir/$unit"
            elif [[ "$opt" == x-systemd.growfs ]]; then
                service="$(systemd-escape --template=systemd-growfs@.service --path "$where")"
                link_endswith "$out_dir/${unit}.wants/$service" "/lib/systemd/system/systemd-growfs@.service"
            elif [[ "$opt" == bg ]] && [[ "$fstype" =~ ^(nfs|nfs4)$ ]]; then
                # We "convert" nfs bg mounts to fg, so we can do the job-control
                # ourselves
                grep -qE "^Options=.*\bx-systemd.mount-timeout=infinity\b" "$out_dir/$unit"
                grep -qE "^Options=.*\bfg\b.*" "$out_dir/$unit"
            elif [[ "$opt" =~ ^x-systemd\. ]]; then
                echo >&2 "Unhandled mount option: $opt"
                exit 1
            fi
        done
    done
}

: "fstab-generator: regular"
printf "%s\n" "${FSTAB_GENERAL_ROOT[@]}" >"$FSTAB"
cat "$FSTAB"
SYSTEMD_FSTAB="$FSTAB" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
check_fstab_mount_units FSTAB_GENERAL_ROOT "$OUT_DIR"

# Skip the rest when running in a container, as it makes little sense to check
# initrd-related stuff there and fstab-generator might have a bit strange
# behavior during certain tests, like https://github.com/systemd/systemd/issues/27156
if in_container; then
    echo "Running in a container, skipping the rest of the fstab-generator tests..."
    exit 0
fi

# In this mode we treat the entries as "regular" ones
: "fstab-generator: initrd - initrd fstab"
printf "%s\n" "${FSTAB_GENERAL[@]}" >"$FSTAB"
cat "$FSTAB"
SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB="$FSTAB" SYSTEMD_SYSROOT_FSTAB=/dev/null run_and_list "$GENERATOR_BIN" "$OUT_DIR"
SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB="$FSTAB" SYSTEMD_SYSROOT_FSTAB=/dev/null check_fstab_mount_units FSTAB_GENERAL "$OUT_DIR"

# In this mode we prefix the mount target with /sysroot and ignore all mounts
# that don't have the x-initrd.mount flag
: "fstab-generator: initrd - host fstab"
printf "%s\n" "${FSTAB_GENERAL_ROOT[@]}" >"$FSTAB"
cat "$FSTAB"
SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB=/dev/null SYSTEMD_SYSROOT_FSTAB="$FSTAB" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB=/dev/null SYSTEMD_SYSROOT_FSTAB="$FSTAB" check_fstab_mount_units FSTAB_GENERAL_ROOT "$OUT_DIR"

# Check the default stuff that we (almost) always create in initrd
: "fstab-generator: initrd default"
SYSTEMD_PROC_CMDLINE="root=/dev/sda2" SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB=/dev/null SYSTEMD_SYSROOT_FSTAB=/dev/null run_and_list "$GENERATOR_BIN" "$OUT_DIR"
test -e "$OUT_DIR/normal/sysroot.mount"
test -e "$OUT_DIR/normal/systemd-fsck-root.service"
link_eq "$OUT_DIR/normal/initrd-root-fs.target.requires/sysroot.mount" "../sysroot.mount"
link_eq "$OUT_DIR/normal/initrd-root-fs.target.requires/sysroot.mount" "../sysroot.mount"

: "fstab-generator: run as systemd-sysroot-fstab-check in initrd"
ln -svf "$GENERATOR_BIN" /tmp/systemd-sysroot-fstab-check
(! /tmp/systemd-sysroot-fstab-check foo)
(! SYSTEMD_IN_INITRD=0 /tmp/systemd-sysroot-fstab-check)
printf "%s\n" "${FSTAB_GENERAL[@]}" >"$FSTAB"
SYSTEMD_IN_INITRD=1 SYSTEMD_SYSROOT_FSTAB="$FSTAB" /tmp/systemd-sysroot-fstab-check

: "fstab-generator: duplicate"
printf "%s\n" "${FSTAB_DUPLICATE[@]}" >"$FSTAB"
cat "$FSTAB"
(! SYSTEMD_FSTAB="$FSTAB" run_and_list "$GENERATOR_BIN" "$OUT_DIR")

: "fstab-generator: invalid"
printf "%s\n" "${FSTAB_INVALID[@]}" >"$FSTAB"
cat "$FSTAB"
# Don't care about the exit code here
SYSTEMD_PROC_CMDLINE="" SYSTEMD_FSTAB="$FSTAB" run_and_list "$GENERATOR_BIN" "$OUT_DIR" || :
# No mounts should get created here
[[ "$(find "$OUT_DIR" -name "*.mount" | wc -l)" -eq 0 ]]

: "fstab-generator: kernel args - fstab=0"
printf "%s\n" "${FSTAB_MINIMAL[@]}" >"$FSTAB"
SYSTEMD_FSTAB="$FSTAB" SYSTEMD_PROC_CMDLINE="fstab=0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
(! SYSTEMD_FSTAB="$FSTAB" check_fstab_mount_units FSTAB_MINIMAL "$OUT_DIR")
SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB="$FSTAB" SYSTEMD_PROC_CMDLINE="fstab=0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
(! SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB="$FSTAB" check_fstab_mount_units FSTAB_MINIMAL "$OUT_DIR")

: "fstab-generator: kernel args - rd.fstab=0"
printf "%s\n" "${FSTAB_MINIMAL[@]}" >"$FSTAB"
SYSTEMD_FSTAB="$FSTAB" SYSTEMD_PROC_CMDLINE="rd.fstab=0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
SYSTEMD_FSTAB="$FSTAB" check_fstab_mount_units FSTAB_MINIMAL "$OUT_DIR"
SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB="$FSTAB" SYSTEMD_PROC_CMDLINE="rd.fstab=0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
(! SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB="$FSTAB" check_fstab_mount_units FSTAB_MINIMAL "$OUT_DIR")

: "fstab-generator: kernel args - systemd.swap=0"
printf "%s\n" "${FSTAB_GENERAL_ROOT[@]}" >"$FSTAB"
cat "$FSTAB"
SYSTEMD_FSTAB="$FSTAB" SYSTEMD_PROC_CMDLINE="systemd.swap=0" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
# No swap units should get created here
[[ "$(find "$OUT_DIR" -name "*.swap" | wc -l)" -eq 0 ]]

# Possible TODO
#   - combine the rootfs & usrfs arguments and mix them with fstab entries
#   - systemd.volatile=
: "fstab-generator: kernel args - root= + rootfstype= + rootflags="
# shellcheck disable=SC2034
EXPECTED_FSTAB=(
    "/dev/disk/by-label/rootfs  /    ext4    noexec,ro   0 1"
)
CMDLINE="root=LABEL=rootfs rootfstype=ext4 rootflags=noexec"
SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB=/dev/null SYSTEMD_SYSROOT_FSTAB=/dev/null SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
# The /proc/cmdline here is a dummy value to tell the in_initrd_host() function
# we're parsing host's fstab, but it's all on the kernel cmdline instead
SYSTEMD_IN_INITRD=1 SYSTEMD_SYSROOT_FSTAB=/proc/cmdline check_fstab_mount_units EXPECTED_FSTAB "$OUT_DIR"

# This is a very basic sanity test that involves manual checks, since adding it
# to the check_fstab_mount_units() function would make it way too complex
# (yet another possible TODO)
: "fstab-generator: kernel args - mount.usr= + mount.usrfstype= + mount.usrflags="
CMDLINE="mount.usr=UUID=be780f43-8803-4a76-9732-02ceda6e9808 mount.usrfstype=ext4 mount.usrflags=noexec,nodev"
SYSTEMD_IN_INITRD=1 SYSTEMD_FSTAB=/dev/null SYSTEMD_SYSROOT_FSTAB=/dev/null SYSTEMD_PROC_CMDLINE="$CMDLINE" run_and_list "$GENERATOR_BIN" "$OUT_DIR"
cat "$OUT_DIR/normal/sysroot-usr.mount" "$OUT_DIR/normal/sysusr-usr.mount"
# The general idea here is to mount the device to /sysusr/usr and then
# bind-mount /sysusr/usr to /sysroot/usr
grep -qE "^What=/dev/disk/by-uuid/be780f43-8803-4a76-9732-02ceda6e9808$" "$OUT_DIR/normal/sysusr-usr.mount"
grep -qE "^Where=/sysusr/usr$" "$OUT_DIR/normal/sysusr-usr.mount"
grep -qE "^Type=ext4$" "$OUT_DIR/normal/sysusr-usr.mount"
grep -qE "^Options=noexec,nodev,ro$" "$OUT_DIR/normal/sysusr-usr.mount"
link_eq "$OUT_DIR/normal/initrd-usr-fs.target.requires/sysusr-usr.mount" "../sysusr-usr.mount"
grep -qE "^What=/sysusr/usr$" "$OUT_DIR/normal/sysroot-usr.mount"
grep -qE "^Where=/sysroot/usr$" "$OUT_DIR/normal/sysroot-usr.mount"
grep -qE "^Options=bind$" "$OUT_DIR/normal/sysroot-usr.mount"
link_eq "$OUT_DIR/normal/initrd-fs.target.requires/sysroot-usr.mount" "../sysroot-usr.mount"
