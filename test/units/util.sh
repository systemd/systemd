#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Utility functions for shell tests

# shellcheck disable=SC2034
[[ -e /var/tmp/.systemd_reboot_count ]] && REBOOT_COUNT="$(</var/tmp/.systemd_reboot_count)" || REBOOT_COUNT=0

assert_ok() {(
    set +ex

    local rc

    "$@"
    rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "FAIL: command '$*' failed with exit code $rc" >&2
        exit 1
    fi
)}

assert_fail() {(
    set +ex

    local rc

    if "$@"; then
        echo "FAIL: command '$*' unexpectedly succeeded" >&2
        exit 1
    fi
)}

assert_eq() {(
    set +ex

    if [[ "${1?}" != "${2?}" ]]; then
        echo "FAIL: expected: '$2' actual: '$1'" >&2
        exit 1
    fi
)}

assert_neq() {(
    set +ex

    if [[ "${1?}" = "${2?}" ]]; then
        echo "FAIL: not expected: '$2' actual: '$1'" >&2
        exit 1
    fi
)}

assert_le() {(
    set +ex

    if [[ "${1:?}" -gt "${2:?}" ]]; then
        echo "FAIL: '$1' > '$2'" >&2
        exit 1
    fi
)}

assert_ge() {(
    set +ex

    if [[ "${1:?}" -lt "${2:?}" ]]; then
        echo "FAIL: '$1' < '$2'" >&2
        exit 1
    fi
)}

assert_in() {(
    set +ex

    if ! [[ "${2?}" =~ ${1?} ]]; then
        echo "FAIL: '$1' not found in:" >&2
        echo "$2" >&2
        exit 1
    fi
)}

assert_not_in() {(
    set +ex

    if [[ "${2?}" =~ ${1?} ]]; then
        echo "FAIL: '$1' found in:" >&2
        echo "$2" >&2
        exit 1
    fi
)}

assert_rc() {(
    set +ex

    local rc exp="${1?}"

    shift
    "$@"
    rc=$?
    assert_eq "$rc" "$exp"
)}

assert_not_reached() {
    echo >&2 "Code should not be reached at ${BASH_SOURCE[1]}:${BASH_LINENO[1]}, function ${FUNCNAME[1]}()"
    exit 1
}

run_and_grep() {(
    set +ex

    local expression
    local log ec
    local exp_ec=0

    # Invert the grep condition - i.e. check if the expression is _not_ in command's output
    if [[ "${1:?}" == "-n" ]]; then
        exp_ec=1
        shift
    fi

    expression="${1:?}"
    shift

    if [[ $# -eq 0 ]]; then
        echo >&2 "FAIL: Not enough arguments for ${FUNCNAME[0]}()"
        return 1
    fi

    log="$(mktemp)"
    if ! "$@" |& tee "${log:?}"; then
        echo >&2 "FAIL: Command '$*' failed"
        return 1
    fi

    grep -qE "$expression" "$log" && ec=0 || ec=$?
    if [[ "$exp_ec" -eq 0 && "$ec" -ne 0 ]]; then
        echo >&2 "FAIL: Expression '$expression' not found in the output of '$*'"
        return 1
    elif [[ "$exp_ec" -ne 0 && "$ec" -eq 0 ]]; then
        echo >&2 "FAIL: Expression '$expression' found in the output of '$*'"
        return 1
    fi

    rm -f "$log"
)}

get_cgroup_hierarchy() {
    case "$(stat -c '%T' -f /sys/fs/cgroup)" in
        cgroup2fs)
            echo "unified"
            ;;
        tmpfs)
            if [[ -d /sys/fs/cgroup/unified && "$(stat -c '%T' -f /sys/fs/cgroup/unified)" == cgroup2fs ]]; then
                echo "hybrid"
            else
                echo "legacy"
            fi
            ;;
        *)
            echo >&2 "Failed to determine host's cgroup hierarchy"
            exit 1
    esac
}

runas() {
    local userid="${1:?}"
    shift
    XDG_RUNTIME_DIR=/run/user/"$(id -u "$userid")" setpriv --reuid="$userid" --init-groups "$@"
}

coverage_create_nspawn_dropin() {
    # If we're collecting coverage, bind mount the $BUILD_DIR into the nspawn
    # container so gcov can update the counters. This is mostly for standalone
    # containers, as machinectl stuff is handled by overriding the systemd-nspawn@.service
    local root="${1:?}"
    local container

    if [[ -z "${COVERAGE_BUILD_DIR:-}" ]]; then
        return 0
    fi

    container="$(basename "$root")"
    mkdir -p "/run/systemd/nspawn"
    echo -ne "[Files]\nBind=$COVERAGE_BUILD_DIR\n" >"/run/systemd/nspawn/${container:?}.nspawn"
}

create_dummy_container() {
    local root="${1:?}"

    if [[ ! -d /usr/share/TEST-13-NSPAWN-container-template ]]; then
        echo >&2 "Missing container template, probably not running in TEST-13-NSPAWN?"
        exit 1
    fi

    mkdir -p "$root"
    chmod 555 "$root"
    cp -a /usr/share/TEST-13-NSPAWN-container-template/* "$root"
    coverage_create_nspawn_dropin "$root"
}

can_do_rootless_nspawn() {
    # Our create_dummy_ddi() uses squashfs and openssl.
    command -v mksquashfs &&
    command -v openssl &&

    # Need to have bpf-lsm
    grep -q bpf /sys/kernel/security/lsm &&
    # ...and libbpf installed
    find /usr/lib* -name "libbpf.so.*" 2>/dev/null | grep . >/dev/null &&

    # Ensure mountfsd/nsresourced are listening
    systemctl start systemd-mountfsd.socket systemd-nsresourced.socket &&

    # mountfsd must be enabled...
    [[ -S /run/systemd/io.systemd.MountFileSystem ]] &&
    # ...and have pidfd support for unprivileged operation.
    systemd-analyze compare-versions "$(uname -r)" ge 6.5 &&
    systemd-analyze compare-versions "$(pkcheck --version | awk '{print $3}')" ge 124 &&

    # nsresourced must be enabled...
    [[ -S /run/systemd/userdb/io.systemd.NamespaceResource ]] &&
    # ...and must support the UserNamespaceInterface.
    ! (SYSTEMD_LOG_TARGET=console varlinkctl call \
           /run/systemd/userdb/io.systemd.NamespaceResource \
           io.systemd.NamespaceResource.AllocateUserRange \
           '{"name":"test-supported","size":65536,"userNamespaceFileDescriptor":0}' \
           2>&1 || true) |
        grep "io.systemd.NamespaceResource.UserNamespaceInterfaceNotSupported" >/dev/null
}

# Bump the reboot counter and call systemctl with the given arguments
systemctl_final() {
    local counter

    if [[ $# -eq 0 ]]; then
        echo >&2 "Missing arguments"
        exit 1
    fi

    [[ -e /var/tmp/.systemd_reboot_count ]] && counter="$(</var/tmp/.systemd_reboot_count)" || counter=0
    echo "$((counter + 1))" >/var/tmp/.systemd_reboot_count

    systemctl "$@"
}

cgroupfs_supports_user_xattrs() {
    local xattr

    xattr="user.supported_$RANDOM"
    # shellcheck disable=SC2064
    trap "setfattr --remove=$xattr /sys/fs/cgroup || :" RETURN

    setfattr --name="$xattr" --value=254 /sys/fs/cgroup
    [[ "$(getfattr --name="$xattr" --absolute-names --only-values /sys/fs/cgroup)" -eq 254 ]]
}

tpm_has_pcr() {
    local algorithm="${1:?}"
    local pcr="${2:?}"

    [[ -f "/sys/class/tpm/tpm0/pcr-$algorithm/$pcr" ]]
}

openssl_supports_kdf() {
    local kdf="${1:?}"

    # The arguments will need to be adjusted to make this work for other KDFs than SSKDF,
    # but let's do that when/if the need arises
    openssl kdf -keylen 16 -kdfopt digest:SHA2-256 -kdfopt key:foo -out /dev/null "$kdf"
}

kernel_supports_lsm() {
    local lsm="${1:?}"
    local items item

    if [[ ! -e /sys/kernel/security/lsm ]]; then
        echo "/sys/kernel/security/lsm doesn't exist, assuming $lsm is not supported"
        return 1
    fi

    mapfile -t -d, items </sys/kernel/security/lsm
    for item in "${items[@]}"; do
        if [[ "$item" == "$lsm" ]]; then
            return 0
        fi
    done

    return 1
}

machine_supports_verity_keyring() {
    # Requires kernel built with certain kconfigs, as listed in README:
    # https://oracle.github.io/kconfigs/?config=UTS_RELEASE&config=DM_VERITY_VERIFY_ROOTHASH_SIG&config=DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING&config=DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING&config=IMA_ARCH_POLICY&config=INTEGRITY_MACHINE_KEYRING
    if grep -q "$(openssl x509 -noout -subject -in /usr/share/mkosi.crt | sed 's/^.*CN=//')" /proc/keys && \
            ( . /etc/os-release; [ "$ID" != "centos" ] || systemd-analyze compare-versions "$VERSION_ID" ge 10 ) && \
            ( . /etc/os-release; [ "$ID" != "debian" ] || [ -z "${VERSION_ID:-}" ] || systemd-analyze compare-versions "$VERSION_ID" ge 13 ) && \
            ( . /etc/os-release; [ "$ID" != "ubuntu" ] || systemd-analyze compare-versions "$VERSION_ID" ge 24.04 ) && \
            systemd-analyze compare-versions "$(cryptsetup --version | sed 's/^cryptsetup \([0-9]*\.[0-9]*\.[0-9]*\) .*/\1/')" ge 2.3.0; then
        return 0
    fi

    return 1
}

install_extension_images() {
        local os_release
        os_release="$(test -e /etc/os-release && echo /etc/os-release || echo /usr/lib/os-release)"

        # Rolling distros like Arch do not set VERSION_ID
        local version_id=""
        if grep -q "^VERSION_ID=" "$os_release"; then
            version_id="$(grep "^VERSION_ID=" "$os_release")"
        fi

        local initdir="/var/tmp/app0"
        mkdir -p "$initdir/usr/lib/extension-release.d" "$initdir/opt"
        grep "^ID=" "$os_release" >"$initdir/usr/lib/extension-release.d/extension-release.app0"
        echo "$version_id" >>"$initdir/usr/lib/extension-release.d/extension-release.app0"
        (
            echo "$version_id"
            echo "SYSEXT_IMAGE_ID=app"
        ) >>"$initdir/usr/lib/extension-release.d/extension-release.app0"
        for scope in system user; do
            mkdir -p "$initdir/usr/lib/systemd/$scope"
            cat >"$initdir/usr/lib/systemd/$scope/app0.service" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/script0.sh
TemporaryFileSystem=/var/lib /home
StateDirectory=app0
RuntimeDirectory=app0
EOF
        done
        cat >"$initdir/opt/script0.sh" <<EOF
#!/usr/bin/env bash
set -e
test -e /usr/lib/os-release
echo bar >\${STATE_DIRECTORY}/foo
cat /usr/lib/extension-release.d/extension-release.app0
EOF
        chmod +x "$initdir/opt/script0.sh"
        echo MARKER=1 >"$initdir/usr/lib/systemd/system/some_file"
        mksquashfs "$initdir" /tmp/app0.raw -noappend
        veritysetup format /tmp/app0.raw /tmp/app0.verity --root-hash-file /tmp/app0.roothash
        openssl smime -sign -nocerts -noattr -binary \
                -in /tmp/app0.roothash \
                -inkey /usr/share/mkosi.key \
                -signer /usr/share/mkosi.crt \
                -outform der \
                -out /tmp/app0.roothash.p7s
        chmod go+r /tmp/app0*

        initdir="/var/tmp/conf0"
        mkdir -p "$initdir/etc/extension-release.d" "$initdir/etc/systemd/system" "$initdir/opt"
        grep "^ID=" "$os_release" >"$initdir/etc/extension-release.d/extension-release.conf0"
        echo "$version_id" >>"$initdir/etc/extension-release.d/extension-release.conf0"
        (
            echo "$version_id"
            echo "CONFEXT_IMAGE_ID=app"
        ) >>"$initdir/etc/extension-release.d/extension-release.conf0"
        echo MARKER_1 >"$initdir/etc/systemd/system/some_file"
        mksquashfs "$initdir" /tmp/conf0.raw -noappend
        veritysetup format /tmp/conf0.raw /tmp/conf0.verity --root-hash-file /tmp/conf0.roothash
        openssl smime -sign -nocerts -noattr -binary \
                -in /tmp/conf0.roothash \
                -inkey /usr/share/mkosi.key \
                -signer /usr/share/mkosi.crt \
                -outform der \
                -out /tmp/conf0.roothash.p7s
        chmod go+r /tmp/conf0*

        initdir="/var/tmp/app1"
        mkdir -p "$initdir/usr/lib/extension-release.d" "$initdir/opt"
        grep "^ID=" "$os_release" >"$initdir/usr/lib/extension-release.d/extension-release.app2"
        (
            echo "$version_id"
            echo "SYSEXT_SCOPE=portable"
            echo "SYSEXT_IMAGE_ID=app"
            echo "SYSEXT_IMAGE_VERSION=1"
            echo "PORTABLE_PREFIXES=app1"
        ) >>"$initdir/usr/lib/extension-release.d/extension-release.app2"
        setfattr -n user.extension-release.strict -v false "$initdir/usr/lib/extension-release.d/extension-release.app2"
        for scope in system user; do
            mkdir -p "$initdir/usr/lib/systemd/$scope"
            cat >"$initdir/usr/lib/systemd/$scope/app1.service" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/script1.sh
TemporaryFileSystem=/home
StateDirectory=app1
RuntimeDirectory=app1
EOF
        done
        cat >"$initdir/opt/script1.sh" <<EOF
#!/usr/bin/env bash
set -e
test -e /usr/lib/os-release
echo baz >\${STATE_DIRECTORY}/foo
cat /usr/lib/extension-release.d/extension-release.app2
EOF
        chmod +x "$initdir/opt/script1.sh"
        echo MARKER=1 >"$initdir/usr/lib/systemd/system/other_file"
        mksquashfs "$initdir" /tmp/app1.raw -noappend

        initdir="/var/tmp/app-nodistro"
        mkdir -p "$initdir/usr/lib/extension-release.d" "$initdir/usr/lib/systemd/system"
        (
            echo "ID=_any"
            echo "ARCHITECTURE=_any"
        ) >"$initdir/usr/lib/extension-release.d/extension-release.app-nodistro"
        echo MARKER=1 >"$initdir/usr/lib/systemd/system/some_file"
        mksquashfs "$initdir" /tmp/app-nodistro.raw -noappend

        initdir="/var/tmp/service-scoped-test"
        mkdir -p "$initdir/etc/extension-release.d" "$initdir/etc/systemd/system"
        (
            echo "ID=_any"
            echo "ARCHITECTURE=_any"
        ) >"$initdir/etc/extension-release.d/extension-release.service-scoped-test"
        echo MARKER_CONFEXT_123 >"$initdir/etc/systemd/system/some_file"
        mksquashfs "$initdir" /etc/service-scoped-test.raw -noappend

        # We need to create a dedicated sysext image to test the reload mechanism. If we share an image to install the
        # 'foo.service' it will be loaded from another test run, which will impact the targeted test.
        initdir="/var/tmp/app-reload"
        mkdir -p "$initdir/usr/lib/extension-release.d" "$initdir/usr/lib/systemd/system"
        (
            echo "ID=_any"
            echo "ARCHITECTURE=_any"
            echo "EXTENSION_RELOAD_MANAGER=1"
        ) >"$initdir/usr/lib/extension-release.d/extension-release.app-reload"
        mkdir -p "$initdir/usr/lib/systemd/system/multi-user.target.d"
        cat >"$initdir/usr/lib/systemd/system/foo.service" <<EOF
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=echo foo

[Install]
WantedBy=multi-user.target
EOF
        echo -e "[Unit]\nUpholds=foo.service" >"$initdir/usr/lib/systemd/system/multi-user.target.d/10-foo-service.conf"
        mksquashfs "$initdir" /tmp/app-reload.raw -noappend
}

restore_locale() {
    if [[ -d /usr/lib/locale/xx_XX.UTF-8 ]]; then
        rmdir /usr/lib/locale/xx_XX.UTF-8
    fi

    if [[ -f /tmp/locale.conf.bak ]]; then
        mv /tmp/locale.conf.bak /etc/locale.conf
    else
        rm -f /etc/locale.conf
    fi

    if [[ -f /tmp/default-locale.bak ]]; then
        mv /tmp/default-locale.bak /etc/default/locale
    else
        rm -rf /etc/default
    fi

    if [[ -f /tmp/locale.gen.bak ]]; then
        mv /tmp/locale.gen.bak /etc/locale.gen
    else
        rm -f /etc/locale.gen
    fi
}

generate_locale() {
    local locale="${1:?}"

    if command -v locale-gen >/dev/null && ! localectl list-locales | grep -F "$locale"; then
        echo "$locale UTF-8" >/etc/locale.gen
        locale-gen "$locale"
    fi
}

built_with_musl() (
    set +ex
    ! systemd-analyze --quiet condition 'ConditionVersion=glibc $= ?*'
)

check_nss_module() (
    set +e

    local name="${1:?}"
    local have=
    local i

    if [[ ! -e /etc/nsswitch.conf ]]; then
        : "/etc/nsswitch.conf not found."
        return 1
    fi

    if ! find /usr/lib* -name "libnss_${name}.so.*" 2>/dev/null | grep . >/dev/null; then
        : "NSS module $name not found."
        return 1
    fi

    if [[ "$name" == systemd ]]; then
        for i in passwd group shadow; do
            if ! grep -qE "^$i:.*[[:space:]]*systemd" /etc/nsswitch.conf; then
                : "systemd NSS module is not enabled for $i database."
                return 1
            fi
        done
    else
        if ! grep -qE "^hosts:.*[[:space:]]*$name" /etc/nsswitch.conf; then
            : "$name NSS module is not enabled for hosts database."
            return 1
        fi
    fi

    return 0
)
