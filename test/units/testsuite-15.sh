#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

maybe_mount_usr_overlay
trap 'maybe_umount_usr_overlay' EXIT

clear_unit() {
    local unit_name="${1:?}"
    local base suffix

    systemctl stop "$unit_name" 2>/dev/null || :
    rm -f  /{etc,run,usr/lib}/systemd/system/"$unit_name"
    rm -fr /{etc,run,usr/lib}/systemd/system/"$unit_name".d
    rm -fr /{etc,run,usr/lib}/systemd/system/"$unit_name".{wants,requires}
    if [[ $unit_name == *@* ]]; then
        base="${unit_name%@*}"
        suffix="${unit_name##*.}"
        systemctl stop "$base@"*."$suffix" 2>/dev/null || :
        rm -f  /{etc,run,usr/lib}/systemd/system/"$base@"*."$suffix"
        rm -fr /{etc,run,usr/lib}/systemd/system/"$base@"*."$suffix".d
        rm -fr /{etc,run,usr/lib}/systemd/system/"$base@"*."$suffix".{wants,requires}
    fi
}

clear_units() {
    for u in "$@"; do
        clear_unit "$u"
    done
    systemctl daemon-reload
}

create_service() {
    local service_name="${1:?}"
    clear_units "${service_name}".service

    cat >/etc/systemd/system/"$service_name".service <<EOF
[Unit]
Description=$service_name unit

[Service]
ExecStart=sleep 100000
EOF
    mkdir -p /{etc,run,usr/lib}/systemd/system/"$service_name".service.{d,wants,requires}
}

create_services() {
    for u in "$@"; do
        create_service "$u"
    done
}

check_ok() {
    x="$(systemctl show --value -p "${2:?}" "${1:?}")"
    case "$x" in
        *${3:?}*) return 0 ;;
        *)        return 1 ;;
    esac
}

check_ko() {
    ! check_ok "$@"
}

testcase_basic_dropins() {
    echo "Testing basic dropins..."

    echo "*** test a wants b wants c"
    create_services test15-a test15-b test15-c
    ln -s ../test15-b.service /etc/systemd/system/test15-a.service.wants/
    ln -s ../test15-c.service /etc/systemd/system/test15-b.service.wants/
    check_ok test15-a Wants test15-b.service
    check_ok test15-b Wants test15-c.service

    echo "*** test a wants,requires b"
    create_services test15-a test15-b test15-c
    ln -s ../test15-b.service /etc/systemd/system/test15-a.service.wants/
    ln -s ../test15-b.service /etc/systemd/system/test15-a.service.requires/
    check_ok test15-a Wants test15-b.service
    check_ok test15-a Requires test15-b.service

    echo "*** test a wants nonexistent"
    create_service test15-a
    ln -s ../nonexistent.service /etc/systemd/system/test15-a.service.wants/
    check_ok test15-a Wants nonexistent.service
    systemctl start test15-a
    systemctl stop  test15-a

    echo "*** test a requires nonexistent"
    ln -sf ../nonexistent.service /etc/systemd/system/test15-a.service.requires/
    systemctl daemon-reload
    check_ok test15-a Requires nonexistent.service

    # 'b' is already loaded when 'c' pulls it in via a dropin.
    echo "*** test a,c require b"
    create_services test15-a test15-b test15-c
    ln -sf ../test15-b.service /etc/systemd/system/test15-a.service.requires/
    ln -sf ../test15-b.service /etc/systemd/system/test15-c.service.requires/
    systemctl start test15-a
    check_ok test15-c Requires test15-b.service
    systemctl stop test15-a test15-b

    # 'b'  is already loaded when 'c' pulls it in via an alias dropin.
    echo "*** test a wants alias"
    create_services test15-a test15-b test15-c
    ln -sf test15-c.service /etc/systemd/system/test15-c1.service
    ln -sf ../test15-c.service  /etc/systemd/system/test15-a.service.wants/
    ln -sf ../test15-c1.service /etc/systemd/system/test15-b.service.wants/
    systemctl start test15-a
    check_ok test15-a Wants test15-c.service
    check_ok test15-b Wants test15-c.service
    systemctl stop test15-a test15-c

    echo "*** test service.d/ top level drop-in"
    create_services test15-a test15-b
    check_ko test15-a ExecCondition "/bin/echo a"
    check_ko test15-b ExecCondition "/bin/echo b"
    mkdir -p /run/systemd/system/service.d
    cat >/run/systemd/system/service.d/override.conf <<EOF
[Service]
ExecCondition=/bin/echo %n
EOF
    systemctl daemon-reload
    check_ok test15-a ExecCondition "/bin/echo test15-a"
    check_ok test15-b ExecCondition "/bin/echo test15-b"
    rm -rf /run/systemd/system/service.d

    clear_units test15-{a,b,c,c1}.service
}

testcase_linked_units() {
    echo "Testing linked units..."
    echo "*** test linked unit (same basename)"

    create_service test15-a
    mv /etc/systemd/system/test15-a.service /
    ln -s /test15-a.service /etc/systemd/system/
    ln -s test15-a.service /etc/systemd/system/test15-b.service

    check_ok test15-a Names test15-a.service
    check_ok test15-a Names test15-b.service

    echo "*** test linked unit (cross basename)"

    mv /test15-a.service /test15-a@.scope
    ln -fs /test15-a@.scope /etc/systemd/system/test15-a.service
    systemctl daemon-reload

    check_ok test15-a Names test15-a.service
    check_ok test15-a Names test15-b.service
    check_ko test15-a Names test15-a@     # test15-a@.scope is the symlink target.
                                          # Make sure it is completely ignored.

    rm /test15-a@.scope
    clear_units test15-{a,b}.service
}

testcase_template_alias() {
    echo "Testing instance alias..."
    echo "*** forward"

    create_service test15-a@
    ln -s test15-a@inst.service /etc/systemd/system/test15-b@inst.service  # alias

    check_ok test15-a@inst Names test15-a@inst.service
    check_ok test15-a@inst Names test15-b@inst.service

    check_ok test15-a@other Names test15-a@other.service
    check_ko test15-a@other Names test15-b@other.service

    echo "*** reverse"

    systemctl daemon-reload

    check_ok test15-b@inst Names test15-a@inst.service
    check_ok test15-b@inst Names test15-b@inst.service

    check_ko test15-b@other Names test15-a@other.service
    check_ok test15-b@other Names test15-b@other.service

    clear_units test15-{a,b}@.service
}

testcase_hierarchical_service_dropins() {
    echo "Testing hierarchical service dropins..."
    echo "*** test service.d/ top level drop-in"
    create_services a-b-c
    check_ko a-b-c ExecCondition "echo service.d"
    check_ko a-b-c ExecCondition "echo a-.service.d"
    check_ko a-b-c ExecCondition "echo a-b-.service.d"
    check_ko a-b-c ExecCondition "echo a-b-c.service.d"

    for dropin in service.d a-.service.d a-b-.service.d a-b-c.service.d; do
        mkdir -p "/run/systemd/system/$dropin"
        cat >"/run/systemd/system/$dropin/override.conf" <<EOF
[Service]
ExecCondition=echo $dropin
EOF
        systemctl daemon-reload
        check_ok a-b-c ExecCondition "echo $dropin"

        # Check that we can start a transient service in presence of the drop-ins
        systemd-run -u a-b-c2.service -p Description='sleepy' sleep infinity

        # The transient setting replaces the default
        check_ok a-b-c2.service Description "sleepy"

        # The override takes precedence for ExecCondition
        # (except the last iteration when it only applies to the other service)
        if [ "$dropin" != "a-b-c.service.d" ]; then
            check_ok a-b-c2.service ExecCondition "echo $dropin"
        fi

        # Check that things are the same after a reload
        systemctl daemon-reload
        check_ok a-b-c2.service Description "sleepy"
        if [ "$dropin" != "a-b-c.service.d" ]; then
            check_ok a-b-c2.service ExecCondition "echo $dropin"
        fi

        systemctl stop a-b-c2.service
    done
    for dropin in service.d a-.service.d a-b-.service.d a-b-c.service.d; do
        rm -rf "/run/systemd/system/$dropin"
    done

    clear_units a-b-c.service
}

testcase_hierarchical_slice_dropins() {
    echo "Testing hierarchical slice dropins..."
    echo "*** test slice.d/ top level drop-in"
    # Slice units don't even need a fragment, so we test the defaults here
    check_ok a-b-c.slice Description "Slice /a/b/c"
    check_ok a-b-c.slice MemoryMax "infinity"

    # Test drop-ins
    for dropin in slice.d a-.slice.d a-b-.slice.d a-b-c.slice.d; do
        mkdir -p "/run/systemd/system/$dropin"
        cat >"/run/systemd/system/$dropin/override.conf" <<EOF
[Slice]
MemoryMax=1000000000
EOF
        systemctl daemon-reload
        check_ok a-b-c.slice MemoryMax "1000000000"

        busctl call \
               org.freedesktop.systemd1 \
               /org/freedesktop/systemd1 \
               org.freedesktop.systemd1.Manager \
               StartTransientUnit 'ssa(sv)a(sa(sv))' \
               'a-b-c.slice' 'replace' \
               2 \
               'Description' s 'slice too' \
               'MemoryMax' t 1000000002 \
               0

        # The override takes precedence for MemoryMax
        check_ok a-b-c.slice MemoryMax "1000000000"
        # The transient setting replaces the default
        check_ok a-b-c.slice Description "slice too"

        # Check that things are the same after a reload
        systemctl daemon-reload
        check_ok a-b-c.slice MemoryMax "1000000000"
        check_ok a-b-c.slice Description "slice too"

        busctl call \
               org.freedesktop.systemd1 \
               /org/freedesktop/systemd1 \
               org.freedesktop.systemd1.Manager \
               StopUnit 'ss' \
               'a-b-c.slice' 'replace'

        rm -f "/run/systemd/system/$dropin/override.conf"
    done

    # Test unit with a fragment
    cat >/run/systemd/system/a-b-c.slice <<EOF
[Slice]
MemoryMax=1000000001
EOF
    systemctl daemon-reload
    check_ok a-b-c.slice MemoryMax "1000000001"

    clear_units a-b-c.slice
}

testcase_transient_service_dropins() {
    echo "Testing dropins for a transient service..."
    echo "*** test transient service drop-ins"

    mkdir -p /etc/systemd/system/service.d
    mkdir -p /etc/systemd/system/a-.service.d
    mkdir -p /etc/systemd/system/a-b-.service.d
    mkdir -p /etc/systemd/system/a-b-c.service.d

    echo -e '[Service]\nStandardInputText=aaa' >/etc/systemd/system/service.d/drop1.conf
    echo -e '[Service]\nStandardInputText=bbb' >/etc/systemd/system/a-.service.d/drop2.conf
    echo -e '[Service]\nStandardInputText=ccc' >/etc/systemd/system/a-b-.service.d/drop3.conf
    echo -e '[Service]\nStandardInputText=ddd' >/etc/systemd/system/a-b-c.service.d/drop4.conf

    # There's no fragment yet, so this fails
    systemctl cat a-b-c.service && exit 1

    # xxx → eHh4Cg==
    systemd-run -u a-b-c.service -p StandardInputData=eHh4Cg== sleep infinity

    data=$(systemctl show -P StandardInputData a-b-c.service)
    # xxx\naaa\n\bbb\nccc\nddd\n → eHh4…
    test "$data" = "eHh4CmFhYQpiYmIKY2NjCmRkZAo="

    # Do a reload and check again
    systemctl daemon-reload
    data=$(systemctl show -P StandardInputData a-b-c.service)
    test "$data" = "eHh4CmFhYQpiYmIKY2NjCmRkZAo="

    clear_units a-b-c.service
    rm /etc/systemd/system/service.d/drop1.conf \
       /etc/systemd/system/a-.service.d/drop2.conf \
       /etc/systemd/system/a-b-.service.d/drop3.conf
}

testcase_transient_slice_dropins() {
    echo "Testing dropins for a transient slice..."
    echo "*** test transient slice drop-ins"

    # FIXME: implement reloading of individual units.
    #
    # The settings here are loaded twice. For most settings it doesn't matter,
    # but Documentation is not deduplicated, so we current get repeated entried
    # which is a bug.

    mkdir -p /etc/systemd/system/slice.d
    mkdir -p /etc/systemd/system/a-.slice.d
    mkdir -p /etc/systemd/system/a-b-.slice.d
    mkdir -p /etc/systemd/system/a-b-c.slice.d

    echo -e '[Unit]\nDocumentation=man:drop1' >/etc/systemd/system/slice.d/drop1.conf
    echo -e '[Unit]\nDocumentation=man:drop2' >/etc/systemd/system/a-.slice.d/drop2.conf
    echo -e '[Unit]\nDocumentation=man:drop3' >/etc/systemd/system/a-b-.slice.d/drop3.conf
    echo -e '[Unit]\nDocumentation=man:drop4' >/etc/systemd/system/a-b-c.slice.d/drop4.conf

    # Invoke daemon-reload to make sure that the call below doesn't fail
    systemctl daemon-reload

    # No fragment is required, so this works
    systemctl cat a-b-c.slice

    busctl call \
           org.freedesktop.systemd1 \
           /org/freedesktop/systemd1 \
           org.freedesktop.systemd1.Manager \
           StartTransientUnit 'ssa(sv)a(sa(sv))' \
           'a-b-c.slice' 'replace' \
           1 \
           'Documentation' as 1 'man:drop5' \
           0

    data=$(systemctl show -P Documentation a-b-c.slice)
    test "$data" = "man:drop1 man:drop2 man:drop3 man:drop4 man:drop5 man:drop1 man:drop2 man:drop3 man:drop4"

    # Do a reload and check again
    systemctl daemon-reload
    data=$(systemctl show -P Documentation a-b-c.slice)
    test "$data" = "man:drop5 man:drop1 man:drop2 man:drop3 man:drop4"

    clear_units a-b-c.slice
    rm /etc/systemd/system/slice.d/drop1.conf \
       /etc/systemd/system/a-.slice.d/drop2.conf \
       /etc/systemd/system/a-b-.slice.d/drop3.conf
}

testcase_template_dropins() {
    echo "Testing template dropins..."

    create_services foo bar@ yup@

    # Declare some deps to check if the body was loaded
    cat >>/etc/systemd/system/bar@.service <<EOF
[Unit]
After=bar-template-after.device
EOF

    cat >>/etc/systemd/system/yup@.service <<EOF
[Unit]
After=yup-template-after.device
EOF

    ln -s /etc/systemd/system/bar@.service /etc/systemd/system/foo.service.wants/bar@1.service
    check_ok foo Wants bar@1.service

    echo "*** test bar-alias@.service→bar@.service, but instance symlinks point to yup@.service ***"
    ln -s bar@.service  /etc/systemd/system/bar-alias@.service
    ln -s bar@1.service /etc/systemd/system/bar-alias@1.service
    ln -s yup@.service  /etc/systemd/system/bar-alias@2.service
    ln -s yup@3.service /etc/systemd/system/bar-alias@3.service

    # create some dropin deps
    mkdir -p /etc/systemd/system/bar@{,0,1,2,3}.service.requires/
    mkdir -p /etc/systemd/system/yup@{,0,1,2,3}.service.requires/
    mkdir -p /etc/systemd/system/bar-alias@{,0,1,2,3}.service.requires/

    ln -s ../bar-template-requires.device /etc/systemd/system/bar@.service.requires/
    ln -s ../bar-0-requires.device /etc/systemd/system/bar@0.service.requires/
    ln -s ../bar-1-requires.device /etc/systemd/system/bar@1.service.requires/
    ln -s ../bar-2-requires.device /etc/systemd/system/bar@2.service.requires/
    ln -s ../bar-3-requires.device /etc/systemd/system/bar@3.service.requires/

    ln -s ../yup-template-requires.device /etc/systemd/system/yup@.service.requires/
    ln -s ../yup-0-requires.device /etc/systemd/system/yup@0.service.requires/
    ln -s ../yup-1-requires.device /etc/systemd/system/yup@1.service.requires/
    ln -s ../yup-2-requires.device /etc/systemd/system/yup@2.service.requires/
    ln -s ../yup-3-requires.device /etc/systemd/system/yup@3.service.requires/

    ln -s ../bar-alias-template-requires.device /etc/systemd/system/bar-alias@.service.requires/
    ln -s ../bar-alias-0-requires.device /etc/systemd/system/bar-alias@0.service.requires/
    ln -s ../bar-alias-1-requires.device /etc/systemd/system/bar-alias@1.service.requires/
    ln -s ../bar-alias-2-requires.device /etc/systemd/system/bar-alias@2.service.requires/
    ln -s ../bar-alias-3-requires.device /etc/systemd/system/bar-alias@3.service.requires/

    systemctl daemon-reload

    echo '*** bar@0 is aliased by bar-alias@0 ***'
    systemctl show -p Names,Requires bar@0
    systemctl show -p Names,Requires bar-alias@0
    check_ok bar@0 Names bar@0
    check_ok bar@0 Names bar-alias@0

    check_ok bar@0 After bar-template-after.device

    check_ok bar@0 Requires bar-0-requires.device
    check_ok bar@0 Requires bar-alias-0-requires.device
    check_ok bar@0 Requires bar-template-requires.device
    check_ok bar@0 Requires bar-alias-template-requires.device
    check_ko bar@0 Requires yup-template-requires.device

    check_ok bar-alias@0 After bar-template-after.device

    check_ok bar-alias@0 Requires bar-0-requires.device
    check_ok bar-alias@0 Requires bar-alias-0-requires.device
    check_ok bar-alias@0 Requires bar-template-requires.device
    check_ok bar-alias@0 Requires bar-alias-template-requires.device
    check_ko bar-alias@0 Requires yup-template-requires.device
    check_ko bar-alias@0 Requires yup-0-requires.device

    echo '*** bar@1 is aliased by bar-alias@1 ***'
    systemctl show -p Names,Requires bar@1
    systemctl show -p Names,Requires bar-alias@1
    check_ok bar@1 Names bar@1
    check_ok bar@1 Names bar-alias@1

    check_ok bar@1 After bar-template-after.device

    check_ok bar@1 Requires bar-1-requires.device
    check_ok bar@1 Requires bar-alias-1-requires.device
    check_ok bar@1 Requires bar-template-requires.device
    # See https://github.com/systemd/systemd/pull/13119#discussion_r308145418
    check_ok bar@1 Requires bar-alias-template-requires.device
    check_ko bar@1 Requires yup-template-requires.device
    check_ko bar@1 Requires yup-1-requires.device

    check_ok bar-alias@1 After bar-template-after.device

    check_ok bar-alias@1 Requires bar-1-requires.device
    check_ok bar-alias@1 Requires bar-alias-1-requires.device
    check_ok bar-alias@1 Requires bar-template-requires.device
    check_ok bar-alias@1 Requires bar-alias-template-requires.device
    check_ko bar-alias@1 Requires yup-template-requires.device
    check_ko bar-alias@1 Requires yup-1-requires.device

    echo '*** bar-alias@2 aliases yup@2, bar@2 is independent ***'
    systemctl show -p Names,Requires bar@2
    systemctl show -p Names,Requires bar-alias@2
    check_ok bar@2 Names bar@2
    check_ko bar@2 Names bar-alias@2

    check_ok bar@2 After bar-template-after.device

    check_ok bar@2 Requires bar-2-requires.device
    check_ko bar@2 Requires bar-alias-2-requires.device
    check_ok bar@2 Requires bar-template-requires.device
    check_ko bar@2 Requires bar-alias-template-requires.device
    check_ko bar@2 Requires yup-template-requires.device
    check_ko bar@2 Requires yup-2-requires.device

    check_ko bar-alias@2 After bar-template-after.device

    check_ko bar-alias@2 Requires bar-2-requires.device
    check_ok bar-alias@2 Requires bar-alias-2-requires.device
    check_ko bar-alias@2 Requires bar-template-requires.device
    check_ok bar-alias@2 Requires bar-alias-template-requires.device
    check_ok bar-alias@2 Requires yup-template-requires.device
    check_ok bar-alias@2 Requires yup-2-requires.device

    echo '*** bar-alias@3 aliases yup@3, bar@3 is independent ***'
    systemctl show -p Names,Requires bar@3
    systemctl show -p Names,Requires bar-alias@3
    check_ok bar@3 Names bar@3
    check_ko bar@3 Names bar-alias@3

    check_ok bar@3 After bar-template-after.device

    check_ok bar@3 Requires bar-3-requires.device
    check_ko bar@3 Requires bar-alias-3-requires.device
    check_ok bar@3 Requires bar-template-requires.device
    check_ko bar@3 Requires bar-alias-template-requires.device
    check_ko bar@3 Requires yup-template-requires.device
    check_ko bar@3 Requires yup-3-requires.device

    check_ko bar-alias@3 After bar-template-after.device

    check_ko bar-alias@3 Requires bar-3-requires.device
    check_ok bar-alias@3 Requires bar-alias-3-requires.device
    check_ko bar-alias@3 Requires bar-template-requires.device
    check_ok bar-alias@3 Requires bar-alias-template-requires.device
    check_ok bar-alias@3 Requires yup-template-requires.device
    check_ok bar-alias@3 Requires yup-3-requires.device

    clear_units foo.service {bar,yup,bar-alias}@{,1,2,3}.service
}

testcase_alias_dropins() {
    echo "Testing alias dropins..."

    echo "*** test a wants b1 alias of b"
    create_services test15-a test15-b
    ln -sf test15-b.service /etc/systemd/system/test15-b1.service
    ln -sf ../test15-b1.service /etc/systemd/system/test15-a.service.wants/
    check_ok test15-a Wants test15-b.service
    systemctl start test15-a
    systemctl --quiet is-active test15-b
    systemctl stop test15-a test15-b
    rm /etc/systemd/system/test15-b1.service
    clear_units test15-{a,b}.service

    # Check that dependencies don't vary.
    echo "*** test 2"
    create_services test15-a test15-x test15-y
    mkdir -p /etc/systemd/system/test15-a1.service.wants/
    ln -sf test15-a.service /etc/systemd/system/test15-a1.service
    ln -sf ../test15-x.service /etc/systemd/system/test15-a.service.wants/
    ln -sf ../test15-y.service /etc/systemd/system/test15-a1.service.wants/
    check_ok test15-a1 Wants test15-x.service # see [1]
    check_ok test15-a1 Wants test15-y.service
    systemctl start test15-a
    check_ok test15-a1 Wants test15-x.service # see [2]
    check_ok test15-a1 Wants test15-y.service
    systemctl stop test15-a test15-x test15-y
    rm /etc/systemd/system/test15-a1.service

    clear_units test15-{a,x,y}.service
}

testcase_masked_dropins() {
    echo "Testing masked dropins..."

    create_services test15-a test15-b

    # 'b' is masked for both deps
    echo "*** test a wants,requires b is masked"
    ln -sf /dev/null /etc/systemd/system/test15-a.service.wants/test15-b.service
    ln -sf /dev/null /etc/systemd/system/test15-a.service.requires/test15-b.service
    check_ko test15-a Wants test15-b.service
    check_ko test15-a Requires test15-b.service

    # 'a' wants 'b' and 'b' is masked at a lower level
    echo "*** test a wants b, mask override"
    ln -sf ../test15-b.service /etc/systemd/system/test15-a.service.wants/test15-b.service
    ln -sf /dev/null /usr/lib/systemd/system/test15-a.service.wants/test15-b.service
    check_ok test15-a Wants test15-b.service

    # 'a' wants 'b' and 'b' is masked at a higher level
    echo "*** test a wants b, mask"
    ln -sf /dev/null /etc/systemd/system/test15-a.service.wants/test15-b.service
    ln -sf ../test15-b.service /usr/lib/systemd/system/test15-a.service.wants/test15-b.service
    check_ko test15-a Wants test15-b.service

    # 'a' is masked but has an override config file
    echo "*** test a is masked but has an override"
    create_services test15-a test15-b
    ln -sf /dev/null /etc/systemd/system/test15-a.service
    cat >/usr/lib/systemd/system/test15-a.service.d/override.conf <<EOF
[Unit]
After=test15-b.service
EOF
    check_ok test15-a UnitFileState masked

    # 'b1' is an alias for 'b': masking 'b' dep should not influence 'b1' dep
    echo "*** test a wants b, b1, and one is masked"
    create_services test15-a test15-b
    ln -sf test15-b.service /etc/systemd/system/test15-b1.service
    ln -sf /dev/null /etc/systemd/system/test15-a.service.wants/test15-b.service
    ln -sf ../test15-b1.service /usr/lib/systemd/system/test15-a.service.wants/test15-b1.service
    systemctl cat test15-a
    systemctl show -p Wants,Requires test15-a
    systemctl cat test15-b1
    systemctl show -p Wants,Requires test15-b1
    check_ok test15-a Wants test15-b.service
    check_ko test15-a Wants test15-b1.service # the alias does not show up in the list of units
    rm /etc/systemd/system/test15-b1.service

    # 'b1' is an alias for 'b': masking 'b1' should not influence 'b' dep
    echo "*** test a wants b, alias dep is masked"
    create_services test15-a test15-b
    ln -sf test15-b.service /etc/systemd/system/test15-b1.service
    ln -sf /dev/null /etc/systemd/system/test15-a.service.wants/test15-b1.service
    ln -sf ../test15-b.service /usr/lib/systemd/system/test15-a.service.wants/test15-b.service
    check_ok test15-a Wants test15-b.service
    check_ko test15-a Wants test15-b1.service # the alias does not show up in the list of units
    rm /etc/systemd/system/test15-b1.service

    # 'a' has Wants=b.service but also has a masking
    # dropin 'b': 'b' should still be pulled in.
    echo "*** test a wants b both ways"
    create_services test15-a test15-b
    ln -sf /dev/null /etc/systemd/system/test15-a.service.wants/test15-b.service
    cat >/usr/lib/systemd/system/test15-a.service.d/wants-b.conf <<EOF
[Unit]
Wants=test15-b.service
EOF
    check_ok test15-a Wants test15-b.service

    # mask a dropin that points to an nonexistent unit.
    echo "*** test a wants nonexistent is masked"
    create_services test15-a
    ln -sf /dev/null /etc/systemd/system/test15-a.service.requires/nonexistent.service
    ln -sf ../nonexistent.service /usr/lib/systemd/system/test15-a.service.requires/
    check_ko test15-a Requires nonexistent.service

    # 'b' is already loaded when 'c' pulls it in via a dropin but 'b' is
    # masked at a higher level.
    echo "*** test a wants b is masked"
    create_services test15-a test15-b test15-c
    ln -sf ../test15-b.service /etc/systemd/system/test15-a.service.requires/
    ln -sf ../test15-b.service /run/systemd/system/test15-c.service.requires/
    ln -sf /dev/null /etc/systemd/system/test15-c.service.requires/test15-b.service
    systemctl start test15-a
    check_ko test15-c Requires test15-b.service
    systemctl stop test15-a test15-b

    # 'b' is already loaded when 'c' pulls it in via a dropin but 'b' is
    # masked at a lower level.
    echo "*** test a requires b is masked"
    create_services test15-a test15-b test15-c
    ln -sf ../test15-b.service /etc/systemd/system/test15-a.service.requires/
    ln -sf ../test15-b.service /etc/systemd/system/test15-c.service.requires/
    ln -sf /dev/null /run/systemd/system/test15-c.service.requires/test15-b.service
    systemctl start test15-a
    check_ok test15-c Requires test15-b.service
    systemctl stop test15-a test15-b

    # 'a' requires 2 aliases of 'b' and one of them is a mask.
    echo "*** test a requires alias of b, other alias masked"
    create_services test15-a test15-b
    ln -sf test15-b.service /etc/systemd/system/test15-b1.service
    ln -sf test15-b.service /etc/systemd/system/test15-b2.service
    ln -sf /dev/null /etc/systemd/system/test15-a.service.requires/test15-b1.service
    ln -sf ../test15-b1.service /run/systemd/system/test15-a.service.requires/
    ln -sf ../test15-b2.service /usr/lib/systemd/system/test15-a.service.requires/
    check_ok test15-a Requires test15-b

    # Same as above but now 'b' is masked.
    echo "*** test a requires alias of b, b dep masked"
    create_services test15-a test15-b
    ln -sf test15-b.service /etc/systemd/system/test15-b1.service
    ln -sf test15-b.service /etc/systemd/system/test15-b2.service
    ln -sf ../test15-b1.service /run/systemd/system/test15-a.service.requires/
    ln -sf ../test15-b2.service /usr/lib/systemd/system/test15-a.service.requires/
    ln -sf /dev/null /etc/systemd/system/test15-a.service.requires/test15-b.service
    check_ok test15-a Requires test15-b

    clear_units test15-{a,b}.service
}

testcase_invalid_dropins() {
    echo "Testing invalid dropins..."
    # Assertion failed on earlier versions, command exits unsuccessfully on later versions
    systemctl cat nonexistent@.service || true
    create_services a
    systemctl daemon-reload
    # Assertion failed on earlier versions, command exits unsuccessfully on later versions
    systemctl cat a@.service || true
    systemctl stop a
    clear_units a.service
    return 0
}

testcase_symlink_dropin_directory() {
    # For issue #21920.
    echo "Testing symlink drop-in directory..."
    create_services test15-a
    rmdir /{etc,run,usr/lib}/systemd/system/test15-a.service.d
    mkdir -p /tmp/testsuite-15-test15-a-dropin-directory
    ln -s /tmp/testsuite-15-test15-a-dropin-directory /etc/systemd/system/test15-a.service.d
    cat >/tmp/testsuite-15-test15-a-dropin-directory/override.conf <<EOF
[Unit]
Description=hogehoge
EOF
    ln -s /tmp/testsuite-15-test15-a-dropin-directory-nonexistent /run/systemd/system/test15-a.service.d
    touch /tmp/testsuite-15-test15-a-dropin-directory-regular
    ln -s /tmp/testsuite-15-test15-a-dropin-directory-regular /usr/lib/systemd/system/test15-a.service.d
    check_ok test15-a Description hogehoge

    clear_units test15-a.service
}

run_testcases

touch /testok
