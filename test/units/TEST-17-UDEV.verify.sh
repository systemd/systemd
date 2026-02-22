#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# Test for udevadm verify.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# shellcheck disable=SC2317
cleanup() {
    cd /
    rm -rf "${workdir}"
    workdir=
}

workdir="$(mktemp -d)"
trap cleanup EXIT
cd "${workdir}"

cat >"${workdir}/default_output_1_success" <<EOF

1 udev rules files have been checked.
  Success: 1
  Fail:    0
EOF
cat >"${workdir}/default_output_1_fail" <<EOF

1 udev rules files have been checked.
  Success: 0
  Fail:    1
EOF
cat >"${workdir}/output_0_files" <<EOF

0 udev rules files have been checked.
  Success: 0
  Fail:    0
EOF

test_number=0
rules=
exp=
err=
out=
next_test_number() {
    : $((++test_number))

    local num_str
    num_str=$(printf %05d "${test_number}")

    rules="sample-${num_str}.rules"
    exp="sample-${num_str}.exp"
    err="sample-${num_str}.err"
    exo="sample-${num_str}.exo"
    out="sample-${num_str}.out"
}

assert_0_impl() {
    udevadm verify "$@" >"${out}"
    if [ -f "${exo}" ]; then
        diff -u "${exo}" "${out}"
    elif [ -f "${rules}" ]; then
        diff -u "${workdir}/default_output_1_success" "${out}"
    fi
}

assert_0() {
    assert_0_impl "$@"
    next_test_number
}

assert_1_impl() {
    local rc
    set +e
    udevadm verify "$@" >"${out}" 2>"${err}"
    rc=$?
    set -e

    if [ -f "${exp}" ]; then
        diff -u "${exp}" "${err}"
    fi

    if [ -f "${exo}" ]; then
        diff -u "${exo}" "${out}"
    elif [ -f "${rules}" ]; then
        diff -u "${workdir}/default_output_1_fail" "${out}"
    fi
    assert_eq "$rc" 1
}

assert_1() {
    assert_1_impl "$@"
    next_test_number
}

# initialize variables
next_test_number

assert_0 -h
assert_0 --help
assert_0 -V
assert_0 --version
assert_0 -N help
assert_0 --resolve-names help

# unrecognized option '--unknown'
assert_1 --unknown
# option requires an argument -- 'N'
assert_1 -N
# --resolve-names= takes "early" or "never"
assert_1 -N now
# option '--resolve-names' requires an argument
assert_1 --resolve-names
# --resolve-names= takes "early", "late", or "never"
assert_1 --resolve-names=now
# Failed to parse rules file ./nosuchfile: No such file or directory
assert_1 ./nosuchfile
# Failed to parse rules file ./nosuchfile: No such file or directory
assert_1 ./nosuchfile /dev/null
assert_0 /dev/null

rules_dir='etc/udev/rules.d'
mkdir -p "${rules_dir}"
# No rules files found in $PWD
assert_1 --root="${workdir}"

# Directory without rules.
cp "${workdir}/output_0_files" "${exo}"
assert_0 "${rules_dir}"

# Directory with a loop.
ln -s . "${rules_dir}/loop.rules"
assert_0 "${rules_dir}"
rm "${rules_dir}/loop.rules"

# Effectively empty rules.
echo '#' >"${rules_dir}/empty.rules"
assert_0 --root="${workdir}"
: >"${exo}"
assert_0 --root="${workdir}" --no-summary

# Directory with a single *.rules file.
cp "${workdir}/default_output_1_success" "${exo}"
assert_0 "${rules_dir}"

# No rules files found in nosuchdir
assert_1 --root=nosuchdir

cd "${rules_dir}"

# UDEV_LINE_SIZE 16384
printf '%16383s\n' ' ' >"${rules}"
assert_0 "${rules}"

# Failed to parse rules file ${rules}: No buffer space available
printf '%16384s\n' ' ' >"${rules}"
echo "Failed to parse rules file $(pwd)/${rules}: No buffer space available" >"${exp}"
assert_1 "${rules}"

{
    printf 'RUN+="/usr/bin/true",%8170s\\\n' ' '
    printf 'RUN+="/usr/bin/false"%8170s\\\n' ' '
    echo
} >"${rules}"
assert_0 "${rules}"

printf 'RUN+="/usr/bin/true"%8176s\\\n #\n' ' ' ' ' >"${rules}"
echo >>"${rules}"
cat >"${exp}" <<EOF
$(pwd)/${rules}:1 Line is too long, ignored.
$(pwd)/${rules}: udev rules check failed.
EOF
assert_1 "${rules}"

printf '\\\n' >"${rules}"
cat >"${exp}" <<EOF
$(pwd)/${rules}:1 Unexpected EOF after line continuation, line ignored.
$(pwd)/${rules}: udev rules check failed.
EOF
assert_1 --root="${workdir}" "${rules}"

test_syntax_error() {
    local rule msg

    rule="$1"; shift
    msg="$1"; shift

    printf '%s\n' "${rule}" >"${rules}"
    cat >"${exp}" <<EOF
$(pwd)/${rules}:1 ${msg}
$(pwd)/${rules}: udev rules check failed.
EOF
    assert_1 "${rules}"
}

test_style_error() {
    local rule msg

    rule="$1"; shift
    msg="$1"; shift

    printf '%s\n' "${rule}" >"${rules}"
    cat >"${exp}" <<EOF
$(pwd)/${rules}:1 ${msg}
$(pwd)/${rules}: udev rules have style issues.
EOF
    assert_0_impl --no-style "${rules}"
    assert_1_impl "${rules}"
    next_test_number
}

test_syntax_error '=' 'Invalid key/value pair, ignoring.'
test_syntax_error 'ACTION{a}=="b"' 'Invalid attribute for ACTION.'
test_syntax_error 'ACTION:="b"' 'Invalid operator for ACTION.'
test_syntax_error 'ACTION=="b"' 'The line has no effect, ignoring.'
test_syntax_error 'DEVPATH{a}=="b"' 'Invalid attribute for DEVPATH.'
test_syntax_error 'DEVPATH:="b"' 'Invalid operator for DEVPATH.'
test_syntax_error 'KERNEL{a}=="b"' 'Invalid attribute for KERNEL.'
test_syntax_error 'KERNEL:="b"' 'Invalid operator for KERNEL.'
test_syntax_error 'KERNELS{a}=="b"' 'Invalid attribute for KERNELS.'
test_syntax_error 'KERNELS:="b"' 'Invalid operator for KERNELS.'
test_syntax_error 'SYMLINK{a}=="b"' 'Invalid attribute for SYMLINK.'
test_syntax_error 'SYMLINK:="%?"' 'Invalid value "%?" for SYMLINK (char 1: invalid substitution type), ignoring.'
test_syntax_error 'NAME{a}=="b"' 'Invalid attribute for NAME.'
test_syntax_error 'NAME-="b"' 'Invalid operator for NAME.'
test_syntax_error 'NAME+="a"' "NAME key takes '==', '!=', '=', or ':=' operator, assuming '='."
test_syntax_error 'NAME:=""' 'Ignoring NAME="", as udev will not delete any network interfaces.'
test_syntax_error 'NAME="%k"' 'Ignoring NAME="%k", as it will take no effect.'
test_syntax_error 'ENV=="b"' 'Invalid attribute for ENV.'
test_syntax_error 'ENV{a}-="b"' 'Invalid operator for ENV.'
test_syntax_error 'ENV{a}:="b"' "ENV key takes '==', '!=', '=', or '+=' operator, assuming '='."
test_syntax_error 'ENV{ACTION}="b"' "Invalid ENV attribute. 'ACTION' cannot be set."
test_syntax_error 'ENV{a}=i"b"' "Invalid prefix 'i' for 'ENV'. The 'i' prefix can be specified only for '==' or '!=' operator."
test_syntax_error 'ENV{a}+=i"b"' "Invalid prefix 'i' for 'ENV'. The 'i' prefix can be specified only for '==' or '!=' operator."
test_syntax_error 'CONST=="b"' 'Invalid attribute for CONST.'
test_syntax_error 'CONST{a}=="b"' 'Invalid attribute for CONST.'
test_syntax_error 'CONST{arch}="b"' 'Invalid operator for CONST.'
test_syntax_error 'TAG{a}=="b"' 'Invalid attribute for TAG.'
test_syntax_error 'TAG:="a"' "TAG key takes '==', '!=', '=', or '+=' operator, assuming '='."
test_syntax_error 'TAG="%?"' 'Invalid value "%?" for TAG (char 1: invalid substitution type), ignoring.'
test_syntax_error 'TAGS{a}=="b"' 'Invalid attribute for TAGS.'
test_syntax_error 'TAGS:="a"' 'Invalid operator for TAGS.'
test_syntax_error 'SUBSYSTEM{a}=="b"' 'Invalid attribute for SUBSYSTEM.'
test_syntax_error 'SUBSYSTEM:="b"' 'Invalid operator for SUBSYSTEM.'
test_syntax_error 'SUBSYSTEM=="bus", NAME="b"' '"bus" must be specified as "subsystem".'
test_syntax_error 'SUBSYSTEMS{a}=="b"' 'Invalid attribute for SUBSYSTEMS.'
test_syntax_error 'SUBSYSTEMS:="b"' 'Invalid operator for SUBSYSTEMS.'
test_syntax_error 'DRIVER{a}=="b"' 'Invalid attribute for DRIVER.'
test_syntax_error 'DRIVER:="b"' 'Invalid operator for DRIVER.'
test_syntax_error 'DRIVERS{a}=="b"' 'Invalid attribute for DRIVERS.'
test_syntax_error 'DRIVERS:="b"' 'Invalid operator for DRIVERS.'
test_syntax_error 'ATTR="b"' 'Invalid attribute for ATTR.'
test_syntax_error 'ATTR{%}="b"' 'Invalid attribute "%" for ATTR (char 1: invalid substitution type), ignoring.'
test_syntax_error 'ATTR{a}-="b"' 'Invalid operator for ATTR.'
test_syntax_error 'ATTR{a}+="b"' "ATTR key takes '==', '!=', or '=' operator, assuming '='."
test_syntax_error 'ATTR{a}="%?"' 'Invalid value "%?" for ATTR (char 1: invalid substitution type), ignoring.'
test_syntax_error 'SYSCTL=""' 'Invalid attribute for SYSCTL.'
test_syntax_error 'SYSCTL{%}="b"' 'Invalid attribute "%" for SYSCTL (char 1: invalid substitution type), ignoring.'
test_syntax_error 'SYSCTL{a}-="b"' 'Invalid operator for SYSCTL.'
test_syntax_error 'SYSCTL{a}+="b"' "SYSCTL key takes '==', '!=', or '=' operator, assuming '='."
test_syntax_error 'SYSCTL{a}="%?"' 'Invalid value "%?" for SYSCTL (char 1: invalid substitution type), ignoring.'
test_syntax_error 'ATTRS=""' 'Invalid attribute for ATTRS.'
test_syntax_error 'ATTRS{%}=="b", NAME="b"' 'Invalid attribute "%" for ATTRS (char 1: invalid substitution type), ignoring.'
test_syntax_error 'ATTRS{a}-="b"' 'Invalid operator for ATTRS.'
test_syntax_error 'ATTRS{device/}!="a", NAME="b"' "'device' link may not be available in future kernels."
test_syntax_error 'ATTRS{../}!="a", NAME="b"' 'Direct reference to parent sysfs directory, may break in future kernels.'
test_syntax_error 'TEST{a}=="b"' "Failed to parse mode 'a': Invalid argument"
test_syntax_error 'TEST{0}=="%", NAME="b"' 'Invalid value "%" for TEST (char 1: invalid substitution type), ignoring.'
test_syntax_error 'TEST{0644}="b"' 'Invalid operator for TEST.'
test_syntax_error 'PROGRAM{a}=="b"' 'Invalid attribute for PROGRAM.'
test_syntax_error 'PROGRAM-="b"' 'Invalid operator for PROGRAM.'
test_syntax_error 'PROGRAM=="%", NAME="b"' 'Invalid value "%" for PROGRAM (char 1: invalid substitution type), ignoring.'
test_syntax_error 'PROGRAM==i"b"' "Invalid prefix 'i' for PROGRAM."
test_syntax_error 'IMPORT="b"' 'Invalid attribute for IMPORT.'
test_syntax_error 'IMPORT{a}="b"' 'Invalid attribute for IMPORT.'
test_syntax_error 'IMPORT{a}-="b"' 'Invalid operator for IMPORT.'
test_syntax_error 'IMPORT{file}=="%", NAME="b"' 'Invalid value "%" for IMPORT (char 1: invalid substitution type), ignoring.'
test_syntax_error 'IMPORT{file}==i"a", NAME="b"' "Invalid prefix 'i' for IMPORT."
test_syntax_error 'IMPORT{builtin}!="foo"' 'Unknown builtin command: foo'
test_syntax_error 'RESULT{a}=="b"' 'Invalid attribute for RESULT.'
test_syntax_error 'RESULT:="b"' 'Invalid operator for RESULT.'
test_syntax_error 'OPTIONS{a}="b"' 'Invalid attribute for OPTIONS.'
test_syntax_error 'OPTIONS-="b"' 'Invalid operator for OPTIONS.'
test_syntax_error 'OPTIONS!="b"' 'Invalid operator for OPTIONS.'
test_syntax_error 'OPTIONS+="link_priority=a"' "Failed to parse link priority 'a': Invalid argument"
test_syntax_error 'OPTIONS:="log_level=a"' "Failed to parse log level 'a': Invalid argument"
test_syntax_error 'OPTIONS="a", NAME="b"' "Invalid value for OPTIONS key, ignoring: 'a'"
test_syntax_error 'OWNER{a}="b"' 'Invalid attribute for OWNER.'
test_syntax_error 'OWNER-="b"' 'Invalid operator for OWNER.'
test_syntax_error 'OWNER!="b"' 'Invalid operator for OWNER.'
test_syntax_error 'OWNER+="0"' "OWNER key takes '=' or ':=' operator, assuming '='."
# numeric system UID is valid even if it does not exist
SYS_UID_MAX=999
if command -v userdbctl >/dev/null; then
    # For the case if non-default setting is used. E.g. OpenSUSE uses 499.
    SYS_UID_MAX="$(userdbctl user -S --no-legend --no-pager | grep 'end system' | awk '{print $8}')"
    echo "SYS_UID_MAX=$SYS_UID_MAX acquired from userdbctl"
elif [[ -e /etc/login.defs ]]; then
    SYS_UID_MAX=$(awk '$1 == "SYS_UID_MAX" { print $2 }' /etc/login.defs)
    echo "SYS_UID_MAX=$SYS_UID_MAX acquired from /etc/login.defs"
fi
for ((i=0;i<=SYS_UID_MAX;i++)); do
    echo "OWNER=\"$i\""
done >"${rules}"
assert_0 "${rules}"
# invalid user name
test_syntax_error 'OWNER=":nosuchuser:"' "Failed to resolve user ':nosuchuser:', ignoring: Invalid argument"
# nonexistent user
if ! getent passwd nosuchuser >/dev/null; then
    test_syntax_error 'OWNER="nosuchuser"' "Failed to resolve user 'nosuchuser', ignoring: Unknown user"
fi
if ! getent passwd 12345 >/dev/null; then
    test_syntax_error 'OWNER="12345"' "Failed to resolve user '12345', ignoring: Unknown user"
fi
# regular user
if getent passwd testuser >/dev/null; then
    echo 'OWNER="testuser"' >"${rules}"
    udevadm verify "${rules}"
    echo "OWNER=\"$(id -u testuser)\"" >"${rules}"
    udevadm verify "${rules}"
fi
test_syntax_error 'GROUP{a}="b"' 'Invalid attribute for GROUP.'
test_syntax_error 'GROUP-="b"' 'Invalid operator for GROUP.'
test_syntax_error 'GROUP!="b"' 'Invalid operator for GROUP.'
test_syntax_error 'GROUP+="0"' "GROUP key takes '=' or ':=' operator, assuming '='."
# numeric system GID is valid even if it does not exist
SYS_GID_MAX=999
if command -v userdbctl >/dev/null; then
    # For the case if non-default setting is used. E.g. OpenSUSE uses 499.
    SYS_GID_MAX="$(userdbctl group -S --no-legend --no-pager | grep 'end system' | awk '{print $8}')"
    echo "SYS_GID_MAX=$SYS_GID_MAX acquired from userdbctl"
elif [[ -e /etc/login.defs ]]; then
    SYS_GID_MAX=$(awk '$1 == "SYS_GID_MAX" { print $2 }' /etc/login.defs)
    echo "SYS_GID_MAX=$SYS_GID_MAX acquired from /etc/login.defs"
fi
for ((i=0;i<=SYS_GID_MAX;i++)); do
    echo "GROUP=\"$i\""
done >"${rules}"
assert_0 "${rules}"
# invalid group name
test_syntax_error 'GROUP=":nosuchgroup:"' "Failed to resolve group ':nosuchgroup:', ignoring: Invalid argument"
# nonexistent group
if ! getent group nosuchgroup >/dev/null; then
    test_syntax_error 'GROUP="nosuchgroup"' "Failed to resolve group 'nosuchgroup', ignoring: Unknown group"
fi
if ! getent group 12345 >/dev/null; then
    test_syntax_error 'GROUP="12345"' "Failed to resolve group '12345', ignoring: Unknown group"
fi
# regular group
if getent group testuser >/dev/null; then
    echo 'GROUP="testuser"' >"${rules}"
    udevadm verify "${rules}"

    echo "GROUP=\"$(id -g testuser)\"" >"${rules}"
    udevadm verify "${rules}"
fi
test_syntax_error 'MODE{a}="b"' 'Invalid attribute for MODE.'
test_syntax_error 'MODE-="b"' 'Invalid operator for MODE.'
test_syntax_error 'MODE!="b"' 'Invalid operator for MODE.'
test_syntax_error 'MODE+="0"' "MODE key takes '=' or ':=' operator, assuming '='."
test_syntax_error 'MODE="%"' 'Invalid value "%" for MODE (char 1: invalid substitution type), ignoring.'
test_syntax_error 'SECLABEL="b"' 'Invalid attribute for SECLABEL.'
test_syntax_error 'SECLABEL{a}="%"' 'Invalid value "%" for SECLABEL (char 1: invalid substitution type), ignoring.'
test_syntax_error 'SECLABEL{a}!="b"' 'Invalid operator for SECLABEL.'
test_syntax_error 'SECLABEL{a}-="b"' 'Invalid operator for SECLABEL.'
test_syntax_error 'SECLABEL{a}:="b"' "SECLABEL key takes '=' or '+=' operator, assuming '='."
test_syntax_error 'RUN=="b"' 'Invalid operator for RUN.'
test_syntax_error 'RUN-="b"' 'Invalid operator for RUN.'
test_syntax_error 'RUN="%"' 'Invalid value "%" for RUN (char 1: invalid substitution type), ignoring.'
test_syntax_error 'RUN{builtin}+="foo"' "Unknown builtin command 'foo', ignoring."
test_syntax_error 'GOTO{a}="b"' 'Invalid attribute for GOTO.'
test_syntax_error 'GOTO=="b"' 'Invalid operator for GOTO.'
test_syntax_error 'NAME="a", GOTO="b"' 'GOTO="b" has no matching label, ignoring.'
test_syntax_error 'GOTO="a", GOTO="b"
LABEL="a"' 'Contains multiple GOTO keys, ignoring GOTO="b".'
test_syntax_error 'LABEL{a}="b"' 'Invalid attribute for LABEL.'
test_syntax_error 'LABEL=="b"' 'Invalid operator for LABEL.'
test_style_error 'LABEL="b"' 'style: LABEL="b" is unused.'
test_syntax_error 'a="b"' "Invalid key 'a'."
test_syntax_error 'KERNEL=="", KERNEL=="?*", NAME="a"' 'conflicting match expressions, the line has no effect.'
test_syntax_error 'KERNEL=="abc", KERNEL!="abc", NAME="b"' 'conflicting match expressions, the line has no effect.'
test_syntax_error 'KERNEL=="|a|b", KERNEL!="b|a|", NAME="c"' 'conflicting match expressions, the line has no effect.'
test_syntax_error 'KERNEL=="a|b", KERNEL=="c|d|e", NAME="f"' 'conflicting match expressions, the line has no effect.'
# shellcheck disable=SC2016
test_syntax_error 'ENV{DISKSEQ}=="?*", ENV{DEVTYPE}!="partition", ENV{DISKSEQ}!="?*", ENV{ID_IGNORE_DISKSEQ}!="1", SYMLINK+="disk/by-diskseq/$env{DISKSEQ}"' \
                  'conflicting match expressions, the line has no effect.'
test_syntax_error 'ACTION=="a*", ACTION=="bc*", NAME="d"' 'conflicting match expressions, the line has no effect.'
test_syntax_error 'ACTION=="a*|bc*", ACTION=="d*|ef*", NAME="g"' 'conflicting match expressions, the line has no effect.'
test_syntax_error 'KERNEL!="", KERNEL=="?*", NAME="a"' 'duplicate expressions.'
test_syntax_error 'KERNEL=="|a|b", KERNEL=="b|a|", NAME="c"' 'duplicate expressions.'
# shellcheck disable=SC2016
test_syntax_error 'ENV{DISKSEQ}=="?*", ENV{DEVTYPE}!="partition", ENV{DISKSEQ}=="?*", ENV{ID_IGNORE_DISKSEQ}!="1", SYMLINK+="disk/by-diskseq/$env{DISKSEQ}"' \
                  'duplicate expressions.'
test_style_error ',ACTION=="a", NAME="b"' 'style: stray leading comma.'
test_style_error ' ,ACTION=="a", NAME="b"' 'style: stray leading comma.'
test_style_error ', ACTION=="a", NAME="b"' 'style: stray leading comma.'
test_style_error 'ACTION=="a", NAME="b",' 'style: stray trailing comma.'
test_style_error 'ACTION=="a", NAME="b", ' 'style: stray trailing comma.'
test_style_error 'ACTION=="a" NAME="b"' 'style: a comma between tokens is expected.'
test_style_error 'ACTION=="a",, NAME="b"' 'style: more than one comma between tokens.'
test_style_error 'ACTION=="a" , NAME="b"' 'style: stray whitespace before comma.'
test_style_error 'ACTION=="a",NAME="b"' 'style: whitespace after comma is expected.'
test_syntax_error 'RESULT=="a", PROGRAM="b"' 'Reordering RESULT check after PROGRAM assignment.'
test_syntax_error 'RESULT=="a*", PROGRAM="b", RESULT=="*c", PROGRAM="d"' \
                  'Reordering RESULT check after PROGRAM assignment.'

cat >"${rules}" <<'EOF'
KERNEL=="a|b", KERNEL=="a|c", NAME="d"
KERNEL=="a|b", KERNEL!="a|c", NAME="d"
KERNEL!="a", KERNEL!="b", NAME="c"
KERNEL=="|a", KERNEL=="|b", NAME="c"
KERNEL=="*", KERNEL=="a*", NAME="b"
KERNEL=="a*", KERNEL=="c*|ab*", NAME="d"
PROGRAM="a", RESULT=="b"
EOF
assert_0 "${rules}"

echo 'GOTO="a"' >"${rules}"
cat >"${exp}" <<EOF
$(pwd)/${rules}:1 GOTO="a" has no matching label, ignoring.
$(pwd)/${rules}:1 The line has no effect any more, dropping.
$(pwd)/${rules}: udev rules check failed.
EOF
assert_1 "${rules}"

cat >"${rules}" <<'EOF'
GOTO="a"
LABEL="a"
EOF
assert_0 "${rules}"

cat >"${rules}" <<'EOF'
GOTO="b"
LABEL="b"
LABEL="b"
EOF
cat >"${exp}" <<EOF
$(pwd)/${rules}:3 style: LABEL="b" is unused.
$(pwd)/${rules}: udev rules have style issues.
EOF
assert_0_impl --no-style "${rules}"
assert_1_impl "${rules}"

cat >"${rules}" <<'EOF'
GOTO="a"
LABEL="a", LABEL="b"
EOF
cat >"${exp}" <<EOF
$(pwd)/${rules}:2 Contains multiple LABEL keys, ignoring LABEL="a".
$(pwd)/${rules}:1 GOTO="a" has no matching label, ignoring.
$(pwd)/${rules}:1 The line has no effect any more, dropping.
$(pwd)/${rules}:2 style: LABEL="b" is unused.
$(pwd)/${rules}: udev rules check failed.
EOF
assert_1 "${rules}"

cat >"${rules}" <<'EOF'
KERNEL!="", KERNEL=="?*", KERNEL=="", NAME="a"
EOF
cat >"${exp}" <<EOF
$(pwd)/${rules}:1 duplicate expressions.
$(pwd)/${rules}:1 conflicting match expressions, the line has no effect.
$(pwd)/${rules}: udev rules check failed.
EOF
assert_1 "${rules}"

cat >"${rules}" <<'EOF'
ACTION=="a"NAME="b"
EOF
cat >"${exp}" <<EOF
$(pwd)/${rules}:1 style: a comma between tokens is expected.
$(pwd)/${rules}:1 style: whitespace between tokens is expected.
$(pwd)/${rules}: udev rules have style issues.
EOF
assert_0_impl --no-style "${rules}"
assert_1_impl "${rules}"
next_test_number

cat >"${rules}" <<'EOF'
ACTION=="a" ,NAME="b"
EOF
cat >"${exp}" <<EOF
$(pwd)/${rules}:1 style: stray whitespace before comma.
$(pwd)/${rules}:1 style: whitespace after comma is expected.
$(pwd)/${rules}: udev rules have style issues.
EOF
assert_0_impl --no-style "${rules}"
assert_1_impl "${rules}"
next_test_number

# udevadm verify --root
#sed "s|sample-[0-9]*.rules|${workdir}/${rules_dir}/&|" sample-*.exp >"${workdir}/${exp}"
cat sample-*.exp >"${workdir}/${exp}"
cd -
assert_1 --root="${workdir}"
cd -

# udevadm verify path/
#sed "s|sample-[0-9]*.rules|${workdir}/${rules_dir}/&|" sample-*.exp >"${workdir}/${exp}"
cat sample-*.exp >"${workdir}/${exp}"
cd -
assert_1 "${rules_dir}"
cd -

exit 0
