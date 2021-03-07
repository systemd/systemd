#! /bin/bash
set -e
set -x

_clear_service () {
    systemctl stop $1.service 2>/dev/null || :
    rm -f  /{etc,run,usr/lib}/systemd/system/$1.service
    rm -fr /{etc,run,usr/lib}/systemd/system/$1.service.d
    rm -fr /{etc,run,usr/lib}/systemd/system/$1.service.{wants,requires}
    if [[ $1 == *@ ]]; then
        systemctl stop $1*.service 2>/dev/null || :
        rm -f  /{etc,run,usr/lib}/systemd/system/$1*.service
        rm -fr /{etc,run,usr/lib}/systemd/system/$1*.service.d
        rm -fr /{etc,run,usr/lib}/systemd/system/$1*.service.{wants,requires}
    fi
}

clear_services () {
    for u in $*; do
        _clear_service $u
    done
    systemctl daemon-reload
}

create_service () {
    clear_services $1

    cat >/etc/systemd/system/$1.service<<EOF
[Unit]
Description=$1 unit

[Service]
ExecStart=/bin/sleep 100000
EOF
    mkdir -p /{etc,run,usr/lib}/systemd/system/$1.service.d
    mkdir -p /etc/systemd/system/$1.service.{wants,requires}
    mkdir -p /run/systemd/system/$1.service.{wants,requires}
    mkdir -p /usr/lib/systemd/system/$1.service.{wants,requires}
}

create_services () {
    for u in $*; do
        create_service $u
    done
}

check_ok () {
    [ $# -eq 3 ] || return

    x="$(systemctl show --value -p $2 $1)"
    case "$x" in
        *$3*) return 0 ;;
        *)    return 1 ;;
    esac
}

check_ko () {
    ! check_ok "$@"
}

test_basic_dropins () {
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
    mkdir -p /usr/lib/systemd/system/service.d
    cat >/usr/lib/systemd/system/service.d/override.conf <<EOF
[Service]
ExecCondition=/bin/echo %n
EOF
    systemctl daemon-reload
    check_ok test15-a ExecCondition "/bin/echo test15-a"
    check_ok test15-b ExecCondition "/bin/echo test15-b"
    rm -rf /usr/lib/systemd/system/service.d

    clear_services test15-a test15-b test15-c
}

test_linked_units () {
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
    clear_services test15-a test15-b
}

test_hierarchical_dropins () {
    echo "Testing hierarchical dropins..."
    echo "*** test service.d/ top level drop-in"
    create_services a-b-c
    check_ko a-b-c ExecCondition "/bin/echo service.d"
    check_ko a-b-c ExecCondition "/bin/echo a-.service.d"
    check_ko a-b-c ExecCondition "/bin/echo a-b-.service.d"
    check_ko a-b-c ExecCondition "/bin/echo a-b-c.service.d"

    for dropin in service.d a-.service.d a-b-.service.d a-b-c.service.d; do
        mkdir -p /usr/lib/systemd/system/$dropin
        echo "
[Service]
ExecCondition=/bin/echo $dropin
        " > /usr/lib/systemd/system/$dropin/override.conf
        systemctl daemon-reload
        check_ok a-b-c ExecCondition "/bin/echo $dropin"
    done
    for dropin in service.d a-.service.d a-b-.service.d a-b-c.service.d; do
        rm -rf /usr/lib/systemd/system/$dropin
    done

    clear_services a-b-c
}

test_template_dropins () {
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

    clear_services foo {bar,yup,bar-alias}@{,1,2,3}
}

test_alias_dropins () {
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
    clear_services test15-a test15-b

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

    clear_services test15-a test15-x test15-y
}

test_masked_dropins () {
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
    cat >/usr/lib/systemd/system/test15-a.service.d/wants-b.conf<<EOF
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

    clear_services test15-a test15-b
}

test_invalid_dropins () {
    echo "Testing invalid dropins..."
    # Assertion failed on earlier versions, command exits unsuccessfully on later versions
    systemctl cat nonexistent@.service || true
    create_services a
    systemctl daemon-reload
    # Assertion failed on earlier versions, command exits unsuccessfully on later versions
    systemctl cat a@.service || true
    systemctl stop a
    clear_services a
    return 0
}

test_basic_dropins
test_linked_units
test_hierarchical_dropins
test_template_dropins
test_alias_dropins
test_masked_dropins
test_invalid_dropins

touch /testok
