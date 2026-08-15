#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# This test makes some basic checks that RPM macros work correctly.
# RPM is a simple C program available on different Linux distros, not only RPM-based ones,
# and even BSD systems, so it must not be a problem to require it.
# rpmspec utility is required (so this test will work with RPM 4 but won't work with RPM 5).
set -eu

BUILD_DIR="${1:?}"
RPM_MACROS_FILE="${BUILD_DIR:?}/src/rpm/macros.systemd"

if ! command -v rpm >/dev/null || ! command -v rpmspec >/dev/null; then
    echo >&2 "Missing necessary utilities (rpm, rpmspec), can't continue"
    exit 1
fi

if [[ ! -f "${RPM_MACROS_FILE:?}" ]]; then
    echo "RPM macros file not found in $RPM_MACROS_FILE!"
    exit 1
fi

at_exit() {
    if [[ -v WORK_DIR && -d "$WORK_DIR" ]]; then
        rm -frv "$WORK_DIR"
    fi
}

trap at_exit EXIT

WORK_DIR="$(mktemp -d)"
RPM_SPEC="$(mktemp "$WORK_DIR/systemd-test-rpm-macros-XXX.spec")"
TEMP_LOG="$(mktemp "$WORK_DIR/out-XXX.log")"

die() {
    echo >&2 "${1:?}"
    exit 1
}

mk_mini_spec() {
    cat >"${RPM_SPEC:?}" <<EOF
%{load:$RPM_MACROS_FILE}
Summary: Test systemd RPM macros
Name: systemd-test-rpm-macros
License: LGPLv2+ and MIT and GPLv2+
Version: 1
Release: 1
%description
%{summary}
END_OF_INITIAL_SPEC
EOF
}

echo "=== Test basic loadability ==="
mk_mini_spec
# ensure its loadability (macros will be just loaded and not used for now)
# also check that rpm supports %load
rpmspec --parse "$RPM_SPEC"

echo "=== Test %systemd_requires ==="
mk_mini_spec
# The idea of tests is the following:
# - make a minimal spec file
# - add macros into its %description section
# - use rpmspec(8) to print spec file with expanded macros
# - check that macros have been expanded as required.
echo "%systemd_requires" >>"$RPM_SPEC"
: >"$TEMP_LOG"
rpmspec --parse "$RPM_SPEC" | tee "$TEMP_LOG"
for i in post preun postun; do
    echo "== Requires($i) =="
    grep "^Requires($i): systemd$" "$TEMP_LOG"
done

echo "=== Test %systemd_ordering ==="
mk_mini_spec
echo "%systemd_ordering" >>"$RPM_SPEC"
: >"$TEMP_LOG"
rpmspec --parse "$RPM_SPEC" | tee "$TEMP_LOG"
for i in post preun postun; do
    echo "== OrderWithRequires($i) =="
    grep "^OrderWithRequires($i): systemd$" "$TEMP_LOG"
done

echo "=== Test macros requiring an argument without specifying such argument ==="
for i in \
    systemd_post \
    systemd_preun \
    systemd_postun \
    systemd_postun_with_restart \
    systemd_user_preun \
    systemd_user_postun \
    systemd_user_postun_with_restart \
    tmpfiles_create \
    tmpfiles_create_package \
    sysusers_create \
    sysusers_create_package
do
    echo "== Macro: $i =="
    mk_mini_spec
    echo "%${i}" >>"$RPM_SPEC"
    if rpmspec --parse "$RPM_SPEC"; then
        die "Unexpected pass with macro $i (no arguments)"
    fi
done

echo "=== Test macros requiring two arguments ==="
for i in \
    tmpfiles_create_package \
    sysusers_create_package
do
    echo "== Macro: $i =="
    # Test with an incorrect number of arguments (0, 1, 3)
    for args in "" "arg1" "arg1 arg2 arg3"; do
        mk_mini_spec
        echo "%${i} $args" >>"$RPM_SPEC"
        if rpmspec --parse "$RPM_SPEC"; then
            die "Unexpected pass with macro $i (arguments: $args)"
        fi
    done

    # Test with the correct number of arguments (2)
    mk_mini_spec
    echo "%${i} arg1 arg2" >>"$RPM_SPEC"
    if ! rpmspec --parse "$RPM_SPEC"; then
        die "Unexpected fail with macro $i (arguments: $args)"
    fi
done


# Test that:
# - *_create_package macros do work correctly
# - shell syntax is correct (https://github.com/systemd/systemd/commit/93406fd37)
# - RPM macros, loaded from macros.in, are actually expanded
echo "=== Test %*_create_package macros ==="
for i in sysusers tmpfiles; do
    echo "== Macro: ${i}_create_package =="

    PKG_DATA_FILE="$(mktemp "$WORK_DIR/pkg-data-XXX")"
    EXP_OUT="$(mktemp "$WORK_DIR/exp-out-XXX.log")"
    CONF_DIR="$(PKG_CONFIG_PATH="${BUILD_DIR}/src/core" pkg-config --variable="${i}dir" systemd)"
    EXTRA_ARGS=()

    if [[ "$i" == tmpfiles ]]; then
        EXTRA_ARGS+=("--create")
    fi

    echo "TEST_DATA" >"$PKG_DATA_FILE"
    mk_mini_spec
    echo "%${i}_create_package TEST_NAME ${PKG_DATA_FILE}" >>"$RPM_SPEC"

    cat >"$EXP_OUT" <<EOF
systemd-$i --replace=$CONF_DIR/TEST_NAME.conf ${EXTRA_ARGS[*]:+${EXTRA_ARGS[@]} }- <<SYSTEMD_INLINE_EOF || :
TEST_DATA
SYSTEMD_INLINE_EOF
EOF

    : >"$TEMP_LOG"
    rpmspec --parse "$RPM_SPEC" | tee "$TEMP_LOG"
    diff "$EXP_OUT" <(grep -A1 -B1 '^TEST_DATA$' "$TEMP_LOG")

    rm -f "$PKG_DATA_FILE"
done
