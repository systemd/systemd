#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
#
# Notes on coverage: when collecting coverage we need the $BUILD_DIR present
# and writable in the container as well. To do this in the least intrusive way,
# two things are going on in the background (only when built with -Db_coverage=true):
#   1) the systemd-nspawn@.service is copied to /etc/systemd/system/ with
#      --bind=$BUILD_DIR appended to the ExecStart= line
#   2) each create_dummy_container() call also creates an .nspawn file in /run/systemd/nspawn/
#      with the last fragment from the path used as a name
#
# The first change is quite self-contained and applies only to containers run
# with machinectl. The second one might cause some unexpected side-effects, namely:
#   - nspawn config (setting) files don't support dropins, so tests that test
#     the config files might need some tweaking (as seen below with
#     the $COVERAGE_BUILD_DIR shenanigans) since they overwrite the .nspawn file
#   - also a note - if /etc/systemd/nspawn/cont-name.nspawn exists, it takes
#     precedence and /run/systemd/nspawn/cont-name.nspawn won't be read even
#     if it exists
#   - also a note 2 - --bind= overrides any Bind= from a config file
#   - in some cases we don't create a test container using create_dummy_container(),
#     so in that case an explicit call to coverage_create_nspawn_dropin() is needed
#
# However, even after jumping through all these hooks, there still might (and is)
# some "incorrectly" missing coverage, especially in the window between spawning
# the inner child process and bind-mounting the coverage $BUILD_DIR
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh


export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_LOG_TARGET=journal

at_exit() {
    set +e

    mountpoint -q /var/lib/machines && umount --recursive /var/lib/machines
    rm -f /run/systemd/nspawn/*.nspawn

    rm -fr /var/tmp/TEST-13-NSPAWN.*
    rm -f /run/verity.d/test-13-nspawn-*.crt
}

trap at_exit EXIT

# check cgroup namespaces
IS_CGNS_SUPPORTED=no
if [[ -f /proc/1/ns/cgroup ]]; then
    IS_CGNS_SUPPORTED=yes
fi

IS_USERNS_SUPPORTED=no
# On some systems (e.g. CentOS 7) the default limit for user namespaces
# is set to 0, which causes the following unshare syscall to fail, even
# with enabled user namespaces support. By setting this value explicitly
# we can ensure the user namespaces support to be detected correctly.
sysctl -w user.max_user_namespaces=10000
if unshare -U bash -c :; then
    IS_USERNS_SUPPORTED=yes
fi

# Mount temporary directory over /var/lib/machines to not pollute the image
mkdir -p /var/lib/machines
mount --bind "$(mktemp --tmpdir=/var/tmp -d)" /var/lib/machines

testcase_sanity() {
    local template root image uuid tmpdir

    tmpdir="$(mktemp -d)"
    template="$(mktemp -d /tmp/nspawn-template.XXX)"
    create_dummy_container "$template"
    # Create a simple image from the just created container template
    image="$(mktemp /var/lib/machines/TEST-13-NSPAWN.image-XXX.img)"
    truncate -s 256M "$image"
    mkfs.ext4 "$image"
    mkdir -p /mnt
    mount -o loop "$image" /mnt
    cp -r "$template"/* /mnt/
    umount /mnt

    systemd-nspawn --help --no-pager
    systemd-nspawn --version

    # --template=
    root="$(mktemp -u -d /var/lib/machines/TEST-13-NSPAWN.sanity.XXX)"
    coverage_create_nspawn_dropin "$root"
    (! systemd-nspawn --register=no --directory="$root" bash -xec 'echo hello')
    # Initialize $root from $template (the $root directory must not exist, hence
    # the `mktemp -u` above)
    systemd-nspawn --register=no --directory="$root" --template="$template" bash -xec 'echo hello'
    systemd-nspawn --register=no --directory="$root" bash -xec 'echo hello; touch /initialized'
    test -e "$root/initialized"
    # Check if the $root doesn't get re-initialized once it's not empty
    systemd-nspawn --register=no --directory="$root" --template="$template" bash -xec 'echo hello'
    test -e "$root/initialized"

    systemd-nspawn --register=no --directory="$root" --ephemeral bash -xec 'touch /ephemeral'
    test ! -e "$root/ephemeral"
    (! systemd-nspawn --register=no \
                      --directory="$root" \
                      --read-only \
                      bash -xec 'touch /nope')
    test ! -e "$root/nope"
    systemd-nspawn --register=no --image="$image" bash -xec 'echo hello'

    # --volatile=
    touch "$root/usr/has-usr"
    # volatile(=yes): rootfs is tmpfs, /usr/ from the OS tree is mounted read only
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --volatile \
                   bash -xec 'test -e /usr/has-usr; touch /usr/read-only && exit 1; touch /nope'
    test ! -e "$root/nope"
    test ! -e "$root/usr/read-only"
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --volatile=yes \
                   bash -xec 'test -e /usr/has-usr; touch /usr/read-only && exit 1; touch /nope'
    test ! -e "$root/nope"
    test ! -e "$root/usr/read-only"
    # volatile=state: rootfs is read-only, /var/ is tmpfs
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --volatile=state \
                   bash -xec 'test -e /usr/has-usr; mountpoint /var; touch /read-only && exit 1; touch /var/nope'
    test ! -e "$root/read-only"
    test ! -e "$root/var/nope"
    # volatile=overlay: tmpfs overlay is mounted over rootfs
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --volatile=overlay \
                   bash -xec 'test -e /usr/has-usr; touch /nope; touch /var/also-nope; touch /usr/nope-too'
    test ! -e "$root/nope"
    test ! -e "$root/var/also-nope"
    test ! -e "$root/usr/nope-too"

    # --volatile= with -U
    touch "$root/usr/has-usr"
    # volatile(=yes): rootfs is tmpfs, /usr/ from the OS tree is mounted read only
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --volatile \
                   -U \
                   bash -xec 'test -e /usr/has-usr; touch /usr/read-only && exit 1; touch /nope'
    test ! -e "$root/nope"
    test ! -e "$root/usr/read-only"
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --volatile=yes \
                   -U \
                   bash -xec 'test -e /usr/has-usr; touch /usr/read-only && exit 1; touch /nope'
    test ! -e "$root/nope"
    test ! -e "$root/usr/read-only"
    # volatile=state: rootfs is read-only, /var/ is tmpfs
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --volatile=state \
                   -U \
                   bash -xec 'test -e /usr/has-usr; mountpoint /var; touch /read-only && exit 1; touch /var/nope'
    test ! -e "$root/read-only"
    test ! -e "$root/var/nope"
    # volatile=overlay: tmpfs overlay is mounted over rootfs
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --volatile=overlay \
                   -U \
                   bash -xec 'test -e /usr/has-usr; touch /nope; touch /var/also-nope; touch /usr/nope-too'
    test ! -e "$root/nope"
    test ! -e "$root/var/also-nope"
    test ! -e "$root/usr/nope-too"

    # --machine=, --hostname=
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --machine="foo-bar.baz" \
                   bash -xec '[[ $(hostname) == foo-bar.baz ]]'
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --hostname="hello.world.tld" \
                   bash -xec '[[ $(hostname) == hello.world.tld ]]'
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --machine="foo-bar.baz" \
                   --hostname="hello.world.tld" \
                   bash -xec '[[ $(hostname) == hello.world.tld ]]'

    # --uuid=
    rm -f "$root/etc/machine-id"
    uuid="deadbeef-dead-dead-beef-000000000000"
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --uuid="$uuid" \
                   bash -xec "[[ \$container_uuid == $uuid ]]"

    # --as-pid2
    systemd-nspawn --register=no --directory="$root" bash -xec '[[ $$ -eq 1 ]]'
    systemd-nspawn --register=no --directory="$root" --as-pid2 bash -xec '[[ $$ -eq 2 ]]'

    # --user=
    # "Fake" getent passwd's bare minimum, so we don't have to pull it in
    # with all the DSO shenanigans
    cat >"$root/bin/getent" <<\EOF
#!/usr/bin/env bash

if [[ $# -eq 0 ]]; then
    :
elif [[ $1 == passwd ]]; then
    echo "testuser:x:1000:1000:testuser:/:/bin/sh"
elif [[ $1 == initgroups ]]; then
    echo "testuser"
fi
EOF
    chmod +x "$root/bin/getent"
    # The useradd is important here so the user is added to /etc/passwd. If the user is not in /etc/passwd,
    # bash will end up loading libnss_systemd.so which breaks when libnss_systemd.so is built with sanitizers
    # as bash isn't invoked with the necessary environment variables for that.
    useradd --root="$root" --uid 1000 --user-group --create-home testuser
    systemd-nspawn --register=no --directory="$root" bash -xec '[[ $USER == root ]]'
    systemd-nspawn --register=no --directory="$root" --user=testuser bash -xec '[[ $USER == testuser ]]'

    # --settings= + .nspawn files
    mkdir -p /run/systemd/nspawn/
    uuid="deadbeef-dead-dead-beef-000000000000"
    echo -ne "[Exec]\nMachineID=deadbeef-dead-dead-beef-111111111111" >/run/systemd/nspawn/foo-bar.nspawn
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --machine=foo-bar \
                   --settings=yes \
                   bash -xec '[[ $container_uuid == deadbeef-dead-dead-beef-111111111111 ]]'
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --machine=foo-bar \
                   --uuid="$uuid" \
                   --settings=yes \
                   bash -xec "[[ \$container_uuid == $uuid ]]"
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --machine=foo-bar \
                   --uuid="$uuid" \
                   --settings=override \
                   bash -xec '[[ $container_uuid == deadbeef-dead-dead-beef-111111111111 ]]'
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --machine=foo-bar \
                   --uuid="$uuid" \
                   --settings=trusted \
                   bash -xec "[[ \$container_uuid == $uuid ]]"

    # Mounts
    mkdir "$tmpdir"/{1,2,3}
    touch "$tmpdir/1/one" "$tmpdir/2/two" "$tmpdir/3/three"
    touch "$tmpdir/foo"
    # --bind=
    systemd-nspawn --register=no \
                   --directory="$root" \
                   ${COVERAGE_BUILD_DIR:+--bind="$COVERAGE_BUILD_DIR"} \
                   --bind="$tmpdir:/foo" \
                   --bind="$tmpdir:/also-foo:noidmap,norbind" \
                   bash -xec 'test -e /foo/foo; touch /foo/bar; test -e /also-foo/bar'
    # --bind= recursive
    rm -f "$tmpdir/bar"
    mount --bind "$tmpdir/1" "$tmpdir/2"
    systemd-nspawn --register=no \
                   --directory="$root" \
                   ${COVERAGE_BUILD_DIR:+--bind="$COVERAGE_BUILD_DIR"} \
                   --bind="$tmpdir:/foo" \
                   --bind="$tmpdir:/also-foo:noidmap,norbind" \
                   bash -xec 'test -e /foo/2/one; ! test -e /foo/2/two; test -e /also-foo/2/two; ! test -e /also-foo/2/one; test -e /foo/foo; touch /foo/bar; test -e /also-foo/bar'
    umount "$tmpdir/2"
    test -e "$tmpdir/bar"
    # --bind-ro=
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --bind-ro="$tmpdir:/foo" \
                   --bind-ro="$tmpdir:/bar:noidmap,norbind" \
                   bash -xec 'test -e /foo/foo; touch /foo/baz && exit 1; touch /bar && exit 1; true'
    # --inaccessible=
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --inaccessible=/var \
                   bash -xec 'touch /var/foo && exit 1; true'
    # --tmpfs=
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --tmpfs=/var:rw,nosuid,noexec \
                   bash -xec 'touch /var/nope'
    test ! -e "$root/var/nope"
    # --overlay=
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --overlay="$tmpdir/1:$tmpdir/2:$tmpdir/3:/var" \
                   bash -xec 'test -e /var/one; test -e /var/two; test -e /var/three; touch /var/foo'
    test -e "$tmpdir/3/foo"
    # --overlay-ro=
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --overlay-ro="$tmpdir/1:$tmpdir/2:$tmpdir/3:/var" \
                   bash -xec 'test -e /var/one; test -e /var/two; test -e /var/three; touch /var/nope && exit 1; true'
    test ! -e "$tmpdir/3/nope"
    rm -fr "$tmpdir"

    # --port (sanity only)
    systemd-nspawn --register=no --network-veth --directory="$root" --port=80 --port=90 true
    systemd-nspawn --register=no --network-veth --directory="$root" --port=80:8080 true
    systemd-nspawn --register=no --network-veth --directory="$root" --port=tcp:80 true
    systemd-nspawn --register=no --network-veth --directory="$root" --port=tcp:80:8080 true
    systemd-nspawn --register=no --network-veth --directory="$root" --port=udp:80 true
    systemd-nspawn --register=no --network-veth --directory="$root" --port=udp:80:8080 --port=tcp:80:8080 true
    (! systemd-nspawn --register=no --network-veth --directory="$root" --port= true)
    (! systemd-nspawn --register=no --network-veth --directory="$root" --port=-1 true)
    (! systemd-nspawn --register=no --network-veth --directory="$root" --port=: true)
    (! systemd-nspawn --register=no --network-veth --directory="$root" --port=icmp:80:8080 true)
    (! systemd-nspawn --register=no --network-veth --directory="$root" --port=tcp::8080 true)
    (! systemd-nspawn --register=no --network-veth --directory="$root" --port=8080: true)
    # Exercise adding/removing ports from an interface
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --network-veth \
                   --port=6667 \
                   --port=80:8080 \
                   --port=udp:53 \
                   --port=tcp:22:2222 \
                   bash -xec 'ip addr add dev host0 10.0.0.10/24; ip a; ip addr del dev host0 10.0.0.10/24'

    # --load-credential=, --set-credential=
    echo "foo bar" >/tmp/cred.path
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --load-credential=cred.path:/tmp/cred.path \
                   --set-credential="cred.set:hello world" \
                   bash -xec '[[ "$(</run/host/credentials/cred.path)" == "foo bar" ]]; [[ "$(</run/host/credentials/cred.set)" == "hello world" ]]'
    # Combine with --user to ensure creds are still readable
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --user=testuser \
                   --no-new-privileges=yes \
                   --load-credential=cred.path:/tmp/cred.path \
                   --set-credential="cred.set:hello world" \
                   bash -xec '[[ "$(</run/host/credentials/cred.path)" == "foo bar" ]]; [[ "$(</run/host/credentials/cred.set)" == "hello world" ]]'
    rm -f /tmp/cred.path

    # Assorted tests
    systemd-nspawn --register=no --directory="$root" --suppress-sync=yes bash -xec 'echo hello'
    systemd-nspawn --capability=help
    systemd-nspawn --register=no --directory="$root" --capability=all bash -xec 'echo hello'
    systemd-nspawn --resolv-conf=help
    systemd-nspawn --timezone=help

    # Handling of invalid arguments
    opts=(
        bind
        bind-ro
        bind-user
        chdir
        console
        inaccessible
        kill-signal
        link-journal
        load-credential
        network-{interface,macvlan,ipvlan,veth-extra,bridge,zone}
        no-new-privileges
        oom-score-adjust
        overlay
        overlay-ro
        personality
        pivot-root
        port
        private-users
        private-users-ownership
        register
        resolv-conf
        rlimit
        root-hash
        root-hash-sig
        set-credential
        settings
        suppress-sync
        timezone
        tmpfs
        uuid
    )
    for opt in "${opts[@]}"; do
        (! systemd-nspawn "--$opt")
        [[ "$opt" == network-zone ]] && continue
        (! systemd-nspawn "--$opt=''")
        (! systemd-nspawn "--$opt=%\$š")
    done
    (! systemd-nspawn --volatile="")
    (! systemd-nspawn --volatile=-1)
    (! systemd-nspawn --rlimit==)
}

nspawn_settings_cleanup() {
    for dev in sd-host-only sd-shared{1,2,3} sd-macvlan{1,2} sd-ipvlan{1,2}; do
        ip link del "$dev" || :
    done

    return 0
}

testcase_nspawn_settings() {
    local root container dev private_users wlan_names

    mkdir -p /run/systemd/nspawn
    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.nspawn-settings.XXX)"
    container="$(basename "$root")"
    create_dummy_container "$root"
    rm -f "/etc/systemd/nspawn/$container.nspawn"
    mkdir -p "$root/tmp" "$root"/opt/{tmp,inaccessible,also-inaccessible}

    # add virtual wlan interfaces
    if modprobe mac80211_hwsim radios=2; then
        wlan_names="wlan0 wlan1:wl-renamed1"
    fi

    for dev in sd-host-only sd-shared{1,2,3} sd-macvlan{1,2} sd-macvlanloong sd-ipvlan{1,2} sd-ipvlanlooong; do
        ip link add "$dev" type dummy
    done
    udevadm settle --timeout=30
    ip link property add dev sd-shared3 altname sd-altname3 altname sd-altname-tooooooooooooo-long
    ip link
    trap nspawn_settings_cleanup RETURN

    # Let's start with one huge config to test as much as we can at once
    cat >"/run/systemd/nspawn/$container.nspawn" <<EOF
[Exec]
Boot=no
Ephemeral=no
ProcessTwo=no
Parameters=bash /entrypoint.sh "foo bar" 'bar baz'
Environment=FOO=bar
Environment=BAZ="hello world"
User=root
WorkingDirectory=/tmp
Capability=CAP_BLOCK_SUSPEND CAP_BPF CAP_CHOWN
DropCapability=CAP_AUDIT_CONTROL CAP_AUDIT_WRITE
AmbientCapability=CAP_BPF CAP_CHOWN
NoNewPrivileges=no
MachineID=f28f129b51874b1280a89421ec4b4ad4
PrivateUsers=no
NotifyReady=no
SystemCallFilter=@basic-io @chown
SystemCallFilter=~ @clock
LimitNOFILE=1024:2048
LimitRTPRIO=8:16
OOMScoreAdjust=32
CPUAffinity=0,0-5,1-5
Hostname=nspawn-settings
ResolvConf=copy-host
Timezone=delete
LinkJournal=no
SuppressSync=no

[Files]
ReadOnly=no
Volatile=no
TemporaryFileSystem=/tmp
TemporaryFileSystem=/opt/tmp
Inaccessible=/opt/inaccessible
Inaccessible=/opt/also-inaccessible
PrivateUsersOwnership=auto
Overlay=+/var::/var
${COVERAGE_BUILD_DIR:+"Bind=$COVERAGE_BUILD_DIR"}

[Network]
Private=yes
VirtualEthernet=yes
VirtualEthernetExtra=my-fancy-veth1
VirtualEthernetExtra=fancy-veth2:my-fancy-veth2
Interface=sd-shared1 sd-shared2:sd-renamed2 sd-shared3:sd-altname3 ${wlan_names:-}
MACVLAN=sd-macvlan1 sd-macvlan2:my-macvlan2 sd-macvlanloong
IPVLAN=sd-ipvlan1 sd-ipvlan2:my-ipvlan2 sd-ipvlanlooong
Zone=sd-zone0
Port=80
Port=81:8181
Port=tcp:60
Port=udp:60:61
EOF
    cat >"$root/entrypoint.sh" <<\EOF
#!/usr/bin/env bash
set -ex

env

[[ "$1" == "foo bar" ]]
[[ "$2" == "bar baz" ]]

[[ "$USER" == root ]]
[[ "$FOO" == bar ]]
[[ "$BAZ" == "hello world" ]]
[[ "$PWD" == /tmp ]]
[[ "$container_uuid" == f28f129b-5187-4b12-80a8-9421ec4b4ad4 ]]
[[ "$(ulimit -S -n)" -eq 1024 ]]
[[ "$(ulimit -H -n)" -eq 2048 ]]
[[ "$(ulimit -S -r)" -eq 8 ]]
[[ "$(ulimit -H -r)" -eq 16 ]]
[[ "$(</proc/self/oom_score_adj)" -eq 32 ]]
[[ "$(hostname)" == nspawn-settings ]]
[[ -e /etc/resolv.conf ]]
[[ ! -e /etc/localtime ]]

mountpoint /tmp
touch /tmp/foo
mountpoint /opt/tmp
touch /opt/tmp/foo
touch /opt/inaccessible/foo && exit 1
touch /opt/also-inaccessible/foo && exit 1
mountpoint /var

ip link
ip link | grep host-only && exit 1
ip link | grep host0@
ip link | grep my-fancy-veth1@
ip link | grep my-fancy-veth2@
ip link | grep sd-shared1
ip link | grep sd-renamed2
ip link | grep sd-shared3
ip link | grep sd-altname3
ip link | grep sd-altname-tooooooooooooo-long
ip link | grep mv-sd-macvlan1@
ip link | grep my-macvlan2@
ip link | grep iv-sd-ipvlan1@
ip link | grep my-ipvlan2@
EOF
    if [[ -n "${wlan_names:-}" ]]; then
        cat >>"$root/entrypoint.sh" <<\EOF
ip link | grep wlan0
ip link | grep wl-renamed1
EOF
    fi

    timeout 30 systemd-nspawn --directory="$root"

    # And now for stuff that needs to run separately
    #
    # Note on the condition below: since our container tree is owned by root,
    # both "yes" and "identity" private users settings will behave the same
    # as PrivateUsers=0:65535, which makes BindUser= fail as the UID already
    # exists there, so skip setting it in such case
    for private_users in "131072:65536" yes identity pick; do
        cat >"/run/systemd/nspawn/$container.nspawn" <<EOF
[Exec]
Hostname=private-users
PrivateUsers=$private_users

[Files]
PrivateUsersOwnership=auto
BindUser=
$([[ "$private_users" =~ (yes|identity) ]] || echo "BindUser=testuser")
${COVERAGE_BUILD_DIR:+"Bind=$COVERAGE_BUILD_DIR"}
EOF
        cat "/run/systemd/nspawn/$container.nspawn"
        chown -R root:root "$root"
        systemd-nspawn --directory="$root" bash -xec '[[ "$(hostname)" == private-users ]]'
    done

    rm -fr "$root" "/run/systemd/nspawn/$container.nspawn"
}

bind_user_cleanup() {
    userdel --force --remove nspawn-bind-user-1
    userdel --force --remove nspawn-bind-user-2
}

testcase_bind_user() {
    local root

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.bind-user.XXX)"
    create_dummy_container "$root"
    useradd --create-home --user-group nspawn-bind-user-1
    useradd --create-home --user-group nspawn-bind-user-2
    trap bind_user_cleanup RETURN
    touch /home/nspawn-bind-user-1/foo
    touch /home/nspawn-bind-user-2/bar
    # Add a couple of POSIX ACLs to test the patch-uid stuff
    mkdir -p "$root/opt"
    setfacl -R -m 'd:u:nspawn-bind-user-1:rwX' -m 'u:nspawn-bind-user-1:rwX' "$root/opt"
    setfacl -R -m 'd:g:nspawn-bind-user-1:rwX' -m 'g:nspawn-bind-user-1:rwX' "$root/opt"

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-1 \
                   bash -xec 'test -e /run/host/home/nspawn-bind-user-1/foo'

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --private-users-ownership=chown \
                   --bind-user=nspawn-bind-user-1 \
                   --bind-user=nspawn-bind-user-2 \
                   bash -xec 'test -e /run/host/home/nspawn-bind-user-1/foo; test -e /run/host/home/nspawn-bind-user-2/bar'
    chown -R root:root "$root"

    # User/group name collision
    echo "nspawn-bind-user-2:x:1000:1000:nspawn-bind-user-2:/home/nspawn-bind-user-2:/bin/bash" >"$root/etc/passwd"
    (! systemd-nspawn --directory="$root" \
                      --private-users=pick \
                      --bind-user=nspawn-bind-user-1 \
                      --bind-user=nspawn-bind-user-2 \
                      true)
    rm -f "$root/etc/passwd"

    echo "nspawn-bind-user-2:x:1000:" >"$root/etc/group"
    (! systemd-nspawn --directory="$root" \
                      --private-users=pick \
                      --bind-user=nspawn-bind-user-1 \
                      --bind-user=nspawn-bind-user-2 \
                      true)
    rm -f "$root/etc/group"

    rm -fr "$root"
}

testcase_bind_user_shell() {
    local root

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.bind-user.XXX)"
    create_dummy_container "$root"
    useradd --create-home --user-group --shell=/usr/bin/bash nspawn-bind-user-1
    useradd --create-home --user-group --shell=/usr/bin/sh   nspawn-bind-user-2
    trap bind_user_cleanup RETURN

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-1 \
                   bash -xec 'grep -qv "\"shell\"" /run/host/userdb/nspawn-bind-user-1.user'

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-1 \
                   --bind-user-shell=no \
                   bash -xec 'grep -qv "\"shell\"" /run/host/userdb/nspawn-bind-user-1.user'

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-1 \
                   --bind-user-shell=yes \
                   bash -xec 'grep -q "\"shell\":\"/usr/bin/bash\"" /run/host/userdb/nspawn-bind-user-1.user'

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-1 \
                   --bind-user-shell=/bin/bash \
                   bash -xec 'grep -q "\"shell\":\"/bin/bash\"" /run/host/userdb/nspawn-bind-user-1.user'

    (! systemd-nspawn --directory="$root" \
                      --private-users=pick \
                      --bind-user=nspawn-bind-user-1 \
                      --bind-user-shell=bad-argument \
                      bash -xec 'true')

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-1 \
                   --bind-user=nspawn-bind-user-2 \
                   bash -xec 'grep -qv "\"shell\"" /run/host/userdb/nspawn-bind-user-1.user && grep -qv "\"shell\"" /run/host/userdb/nspawn-bind-user-2.user'

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-1 \
                   --bind-user=nspawn-bind-user-2 \
                   --bind-user-shell=yes \
                   bash -xec 'grep -q "\"shell\":\"/usr/bin/bash\"" /run/host/userdb/nspawn-bind-user-1.user && grep -q "\"shell\":\"/usr/bin/sh\"" /run/host/userdb/nspawn-bind-user-2.user'

    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-1 \
                   --bind-user=nspawn-bind-user-2 \
                   --bind-user-shell=/bin/sh \
                   bash -xec 'grep -q "\"shell\":\"/bin/sh\"" /run/host/userdb/nspawn-bind-user-1.user && grep -q "\"shell\":\"/bin/sh\"" /run/host/userdb/nspawn-bind-user-2.user'

    mach=$(basename "$root")
    mkdir -p /run/systemd/nspawn
    conf=/run/systemd/nspawn/"$mach".nspawn

    cat <<'EOF' >"$conf"
# [Files]
# BindUserShell=no by default
EOF
    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-2 \
                   bash -xec 'grep -qv "\"shell\"" /run/host/userdb/nspawn-bind-user-2.user'

    cat <<'EOF' >"$conf"
[Files]
BindUserShell=no
EOF
    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-2 \
                   bash -xec 'grep -qv "\"shell\"" /run/host/userdb/nspawn-bind-user-2.user'

    cat <<'EOF' >"$conf"
[Files]
BindUserShell=yes
EOF
    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-2 \
                   bash -xec 'grep -q "\"shell\":\"/usr/bin/sh\"" /run/host/userdb/nspawn-bind-user-2.user'

    cat <<'EOF' >"$conf"
[Files]
BindUserShell=/bin/sh
EOF
    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --bind-user=nspawn-bind-user-2 \
                   bash -xec 'grep -q "\"shell\":\"/bin/sh\"" /run/host/userdb/nspawn-bind-user-2.user'

    cat <<'EOF' >"$conf"
# [Files]
# BindUserShell=no default doesn't override
EOF
    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --settings=override \
                   --bind-user=nspawn-bind-user-2 \
                   --bind-user-shell=yes \
                   bash -xec 'grep -q "\"shell\":\"/usr/bin/sh\"" /run/host/userdb/nspawn-bind-user-2.user'

    cat <<'EOF' >"$conf"
[Files]
BindUserShell=no
EOF
    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --settings=override \
                   --bind-user=nspawn-bind-user-2 \
                   --bind-user-shell=yes \
                   bash -xec 'grep -qv "\"shell\"" /run/host/userdb/nspawn-bind-user-2.user'

    cat <<'EOF' >"$conf"
[Files]
BindUserShell=no
EOF
    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --settings=override \
                   --bind-user=nspawn-bind-user-2 \
                   --bind-user-shell=/foo \
                   bash -xec 'grep -qv "\"shell\"" /run/host/userdb/nspawn-bind-user-2.user'

    cat <<'EOF' >"$conf"
[Files]
BindUserShell=/bin/sh
EOF
    systemd-nspawn --directory="$root" \
                   --private-users=pick \
                   --settings=override \
                   --bind-user=nspawn-bind-user-2 \
                   --bind-user-shell=yes \
                   bash -xec 'grep -q "\"shell\":\"/bin/sh\"" /run/host/userdb/nspawn-bind-user-2.user'

    rm -fr "$root"
}

testcase_bind_tmp_path() {
    # https://github.com/systemd/systemd/issues/4789
    local root

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.bind-tmp-path.XXX)"
    create_dummy_container "$root"
    : >/tmp/bind
    systemd-nspawn --register=no \
                   --directory="$root" \
                   --bind=/tmp/bind \
                   bash -c 'test -e /tmp/bind'

    rm -fr "$root" /tmp/bind
}

testcase_norbind() {
    # https://github.com/systemd/systemd/issues/13170
    local root

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.norbind-path.XXX)"
    mkdir -p /tmp/binddir/subdir
    echo -n "outer" >/tmp/binddir/subdir/file
    mount -t tmpfs tmpfs /tmp/binddir/subdir
    echo -n "inner" >/tmp/binddir/subdir/file
    create_dummy_container "$root"

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --bind=/tmp/binddir:/mnt:norbind \
                   bash -c 'CONTENT=$(cat /mnt/subdir/file); if [[ $CONTENT != "outer" ]]; then echo "*** unexpected content: $CONTENT"; exit 1; fi'

    umount /tmp/binddir/subdir
    rm -fr "$root" /tmp/binddir/
}

rootidmap_cleanup() {
    local dir="${1:?}"

    mountpoint -q "$dir/bind" && umount "$dir/bind"
    rm -fr "$dir"
}

testcase_rootidmap() {
    local root cmd permissions
    local owner=1000

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.rootidmap-path.XXX)"
    # Create ext4 image, as ext4 supports idmapped-mounts.
    mkdir -p /tmp/rootidmap/bind
    truncate -s $((4096*2048)) /tmp/rootidmap/ext4.img
    mkfs.ext4 /tmp/rootidmap/ext4.img
    mount /tmp/rootidmap/ext4.img /tmp/rootidmap/bind
    trap "rootidmap_cleanup /tmp/rootidmap/" RETURN

    touch /tmp/rootidmap/bind/file
    chown -R "$owner:$owner" /tmp/rootidmap/bind

    create_dummy_container "$root"
    cmd='PERMISSIONS=$(stat -c "%u:%g" /mnt/file); if [[ $PERMISSIONS != "0:0" ]]; then echo "*** wrong permissions: $PERMISSIONS"; return 1; fi; touch /mnt/other_file'
    if ! SYSTEMD_LOG_TARGET=console \
            systemd-nspawn --register=no \
                           --directory="$root" \
                           --bind=/tmp/rootidmap/bind:/mnt:rootidmap \
                           bash -c "$cmd" |& tee nspawn.out; then
        if grep -q "Failed to map ids for bind mount.*: Function not implemented" nspawn.out; then
            echo "idmapped mounts are not supported, skipping the test..."
            return 0
        fi

        return 1
    fi

    permissions=$(stat -c "%u:%g" /tmp/rootidmap/bind/other_file)
    if [[ $permissions != "$owner:$owner" ]]; then
        echo "*** wrong permissions: $permissions"
        [[ "$IS_USERNS_SUPPORTED" == "yes" ]] && return 1
    fi
}

owneridmap_cleanup() {
    local dir="${1:?}"

    mountpoint -q "$dir/bind" && umount "$dir/bind"
    rm -fr "$dir"
}

testcase_owneridmap() {
    local root cmd permissions
    local owner=1000

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.owneridmap-path.XXX)"
    # Create ext4 image, as ext4 supports idmapped-mounts.
    mkdir -p /tmp/owneridmap/bind
    truncate -s $((4096*2048)) /tmp/owneridmap/ext4.img
    mkfs.ext4 /tmp/owneridmap/ext4.img
    mount /tmp/owneridmap/ext4.img /tmp/owneridmap/bind
    trap "owneridmap_cleanup /tmp/owneridmap/" RETURN

    touch /tmp/owneridmap/bind/file
    chown -R "$owner:$owner" /tmp/owneridmap/bind

    # Allow users to read and execute / in order to execute binaries
    chmod o+rx "$root"

    create_dummy_container "$root"

    # --user=
    # "Fake" getent passwd's bare minimum, so we don't have to pull it in
    # with all the DSO shenanigans
    cat >"$root/bin/getent" <<\EOF
#!/usr/bin/env bash

if [[ $# -eq 0 ]]; then
    :
elif [[ $1 == passwd ]]; then
    echo "testuser:x:1010:1010:testuser:/:/bin/sh"
elif [[ $1 == initgroups ]]; then
    echo "testuser"
fi
EOF
    chmod +x "$root/bin/getent"

    # The useradd is important here so the user is added to /etc/passwd. If the user is not in /etc/passwd,
    # bash will end up loading libnss_systemd.so which breaks when libnss_systemd.so is built with sanitizers
    # as bash isn't invoked with the necessary environment variables for that.
    useradd --root="$root" --uid 1010 --user-group --create-home testuser

    cmd='PERMISSIONS=$(stat -c "%u:%g" /home/testuser/file); if [[ $PERMISSIONS != "1010:1010" ]]; then echo "*** wrong permissions: $PERMISSIONS"; return 1; fi; touch /home/testuser/other_file'
    if ! SYSTEMD_LOG_TARGET=console \
            systemd-nspawn --register=no \
                           --directory="$root" \
                           -U \
                           --user=testuser \
                           --bind=/tmp/owneridmap/bind:/home/testuser:owneridmap \
                           ${COVERAGE_BUILD_DIR:+--bind="$COVERAGE_BUILD_DIR"} \
                           bash -c "$cmd" |& tee nspawn.out; then
        if grep -q "Failed to map ids for bind mount.*: Function not implemented" nspawn.out; then
            echo "idmapped mounts are not supported, skipping the test..."
            return 0
        fi

        return 1
    fi

    permissions=$(stat -c "%u:%g" /tmp/owneridmap/bind/other_file)
    if [[ $permissions != "$owner:$owner" ]]; then
        echo "*** wrong permissions: $permissions"
        [[ "$IS_USERNS_SUPPORTED" == "yes" ]] && return 1
    fi
}

testcase_notification_socket() {
    # https://github.com/systemd/systemd/issues/4944
    local root
    local cmd='echo a | ncat -U -u -w 1 /run/host/notify'

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.check_notification_socket.XXX)"
    create_dummy_container "$root"

    systemd-nspawn --register=no --directory="$root" bash -x -c "$cmd"
    systemd-nspawn --register=no --directory="$root" -U bash -x -c "$cmd"

    rm -fr "$root"
}

testcase_os_release() {
    local root entrypoint os_release_source

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.os-release.XXX)"
    create_dummy_container "$root"
    entrypoint="$root/entrypoint.sh"
    cat >"$entrypoint" <<\EOF
#!/usr/bin/env bash
set -ex

. /tmp/os-release
[[ -n "${ID:-}" && "$ID" != "$container_host_id" ]] && exit 1
[[ -n "${VERSION_ID:-}" && "$VERSION_ID" != "$container_host_version_id" ]] && exit 1
[[ -n "${BUILD_ID:-}" && "$BUILD_ID" != "$container_host_build_id" ]] && exit 1
[[ -n "${VARIANT_ID:-}" && "$VARIANT_ID" != "$container_host_variant_id" ]] && exit 1

cd /tmp
(cd /run/host && md5sum os-release) | md5sum -c
EOF
    chmod +x "$entrypoint"

    os_release_source="/etc/os-release"
    if [[ ! -r "$os_release_source" ]]; then
        os_release_source="/usr/lib/os-release"
    elif [[ -L "$os_release_source" ]]; then
        # Ensure that /etc always wins if available
        cp --remove-destination -fv /usr/lib/os-release /etc/os-release
        echo MARKER=1 >>/etc/os-release
    fi

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --bind="$os_release_source:/tmp/os-release" \
                   "${entrypoint##"$root"}"

    if grep -q MARKER /etc/os-release; then
        ln -svrf /usr/lib/os-release /etc/os-release
    fi

    rm -fr "$root"
}

testcase_machinectl_bind() {
    local service_path service_name root container_name ec
    local cmd="timeout 10 bash -c 'until [[ -f /tmp/marker ]] && [[ -f /tmp/marker-varlink ]]; do sleep .5; done'; sleep 3"

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.machinectl-bind.XXX)"
    create_dummy_container "$root"
    container_name="$(basename "$root")"

    service_path="$(mktemp /run/systemd/system/nspawn-machinectl-bind-XXX.service)"
    service_name="${service_path##*/}"
    cat >"$service_path" <<EOF
[Service]
Type=notify
ExecStart=systemd-nspawn --directory="$root" --notify-ready=no bash -xec "$cmd"
EOF

    systemctl daemon-reload
    systemctl start "$service_name"
    touch /tmp/marker
    machinectl bind --mkdir "$container_name" /tmp/marker
    touch /tmp/marker-varlink
    varlinkctl call /run/systemd/machine/io.systemd.Machine io.systemd.Machine.BindMount "{\"name\": \"$container_name\", \"source\": \"/tmp/marker-varlink\", \"mkdir\": true}"

    timeout 10 bash -c "while [[ '\$(systemctl show -P SubState $service_name)' == running ]]; do sleep .2; done"
    ec="$(systemctl show -P ExecMainStatus "$service_name")"
    systemctl stop "$service_name"

    rm -fr "$root" "$service_path"

    return "$ec"
}

testcase_selinux() {
    # Basic test coverage to avoid issues like https://github.com/systemd/systemd/issues/19976
    if ! command -v selinuxenabled >/dev/null || ! selinuxenabled; then
        echo >&2 "SELinux is not enabled, skipping SELinux-related tests"
        return 0
    fi

    local root

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.selinux.XXX)"
    create_dummy_container "$root"
    chcon -R -t container_t "$root"

    systemd-nspawn --register=no \
                   --boot \
                   --directory="$root" \
                   --selinux-apifs-context=system_u:object_r:container_file_t:s0:c0,c1 \
                   --selinux-context=system_u:system_r:container_t:s0:c0,c1

    rm -fr "$root"
}

testcase_ephemeral_config() {
    # https://github.com/systemd/systemd/issues/13297
    local root container_name

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.ephemeral-config.XXX)"
    create_dummy_container "$root"
    container_name="$(basename "$root")"

    mkdir -p /run/systemd/nspawn/
    rm -f "/etc/systemd/nspawn/$container_name.nspawn"
    cat >"/run/systemd/nspawn/$container_name.nspawn" <<EOF
[Files]
${COVERAGE_BUILD_DIR:+"Bind=$COVERAGE_BUILD_DIR"}
BindReadOnly=/tmp/ephemeral-config
EOF
    touch /tmp/ephemeral-config

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --ephemeral \
                   bash -x -c "test -f /tmp/ephemeral-config"

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --ephemeral \
                   --machine=foobar \
                   bash -x -c "! test -f /tmp/ephemeral-config"

    rm -fr "$root" "/run/systemd/nspawn/$container_name.nspawn"
}

matrix_run_one() {
    local use_cgns="${1:?}"
    local api_vfs_writable="${2:?}"
    local root

    if [[ "$use_cgns" == "yes" && "$IS_CGNS_SUPPORTED" == "no" ]];  then
        echo >&2 "CGroup namespaces are not supported, skipping..."
        return 0
    fi

    root="$(mktemp -d "/var/lib/machines/TEST-13-NSPAWN.cgns-$1-api-vfs-writable-$2.XXX")"
    create_dummy_container "$root"

    SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --boot

    SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --private-network \
                       --boot

    if SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --private-users=pick \
                       --boot; then
        [[ "$IS_USERNS_SUPPORTED" == "yes" && "$api_vfs_writable" == "network" ]] && return 1
    else
        [[ "$IS_USERNS_SUPPORTED" == "no" && "$api_vfs_writable" == "network" ]] && return 1
    fi

    if SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --private-network \
                       --private-users=pick \
                       --boot; then
        [[ "$IS_USERNS_SUPPORTED" == "yes" && "$api_vfs_writable" == "yes" ]] && return 1
    else
        [[ "$IS_USERNS_SUPPORTED" == "no" && "$api_vfs_writable" = "yes" ]] && return 1
    fi

    local netns_opt="--network-namespace-path=/proc/self/ns/net"
    local net_opt
    local net_opts=(
        "--network-bridge=lo"
        "--network-interface=lo"
        "--network-ipvlan=lo"
        "--network-macvlan=lo"
        "--network-veth"
        "--network-veth-extra=lo"
        "--network-zone=zone"
    )

    # --network-namespace-path and network-related options cannot be used together
    for net_opt in "${net_opts[@]}"; do
        echo "$netns_opt in combination with $net_opt should fail"
        if SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
            systemd-nspawn --register=no \
                           --directory="$root" \
                           --boot \
                           "$netns_opt" \
                           "$net_opt"; then
            echo >&2 "unexpected pass"
            return 1
        fi
    done

    # allow combination of --network-namespace-path and --private-network
    SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --boot \
                       --private-network \
                       "$netns_opt"

    # test --network-namespace-path works with a network namespace created by "ip netns"
    ip netns add nspawn_test
    netns_opt="--network-namespace-path=/run/netns/nspawn_test"
    SYSTEMD_NSPAWN_USE_CGNS="$use_cgns" SYSTEMD_NSPAWN_API_VFS_WRITABLE="$api_vfs_writable" \
        systemd-nspawn --register=no \
                       --directory="$root" \
                       --network-namespace-path=/run/netns/nspawn_test \
                       ip a | grep -v -E '^1: lo.*UP'
    ip netns del nspawn_test

    rm -fr "$root"

    return 0
}

testcase_api_vfs() {
    local api_vfs_writable

    for api_vfs_writable in yes no network; do
        matrix_run_one no  $api_vfs_writable
        matrix_run_one yes $api_vfs_writable
    done
}

testcase_check_os_release() {
    # https://github.com/systemd/systemd/issues/29185
    local base common_opts root

    base="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.check_os_release_base.XXX)"
    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.check_os_release.XXX)"
    create_dummy_container "$base"
    cp -d "$base"/{bin,sbin,lib} "$root/"
    if [ -d "$base"/lib64 ]; then
        cp -d "$base"/lib64 "$root/"
    fi
    common_opts=(
        --boot
        --register=no
        --directory="$root"
        --bind-ro="$base/usr:/usr"
    )

    # Might be needed to find libraries
    if [ -f "$base/etc/ld.so.cache" ]; then
        common_opts+=("--bind-ro=$base/etc/ld.so.cache:/etc/ld.so.cache")
    fi

    # Empty /etc/ & /usr/
    (! systemd-nspawn "${common_opts[@]}")
    (! SYSTEMD_NSPAWN_CHECK_OS_RELEASE=1 systemd-nspawn "${common_opts[@]}")
    (! SYSTEMD_NSPAWN_CHECK_OS_RELEASE=foo systemd-nspawn "${common_opts[@]}")
    SYSTEMD_NSPAWN_CHECK_OS_RELEASE=0 systemd-nspawn "${common_opts[@]}"

    # Empty /usr/ + a broken /etc/os-release -> /usr/os-release symlink
    ln -svrf "$root/etc/os-release" "$root/usr/os-release"
    (! systemd-nspawn "${common_opts[@]}")
    (! SYSTEMD_NSPAWN_CHECK_OS_RELEASE=1 systemd-nspawn "${common_opts[@]}")
    SYSTEMD_NSPAWN_CHECK_OS_RELEASE=0 systemd-nspawn "${common_opts[@]}"

    rm -fr "$root" "$base"
}

testcase_ip_masquerade() {
    local root

    if ! command -v networkctl >/dev/null; then
        echo "This test requires systemd-networkd, skipping..."
        return 0
    fi

    systemctl unmask systemd-networkd.service
    systemctl edit --runtime --stdin systemd-networkd.service --drop-in=debug.conf <<EOF
[Service]
Environment=SYSTEMD_LOG_LEVEL=debug
EOF
    systemctl start systemd-networkd.service

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.ip_masquerade.XXX)"
    create_dummy_container "$root"

    systemd-run --unit=nspawn-hoge.service \
                systemd-nspawn \
                --register=no \
                --directory="$root" \
                --ephemeral \
                --machine=hoge \
                --network-veth \
                bash -x -c "ip link set host0 up; sleep 30s"

    /usr/lib/systemd/systemd-networkd-wait-online -i ve-hoge --timeout 30s

    # Check IPMasquerade= for ve-* and friends enabled IP forwarding.
    [[ "$(cat /proc/sys/net/ipv4/conf/all/forwarding)" == "1" ]]
    [[ "$(cat /proc/sys/net/ipv4/conf/default/forwarding)" == "1" ]]
    [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" == "1" ]]
    [[ "$(cat /proc/sys/net/ipv6/conf/default/forwarding)" == "1" ]]

    systemctl stop nspawn-hoge.service || :
    systemctl stop systemd-networkd.service
    systemctl mask systemd-networkd.service

    rm -fr "$root"
}

create_dummy_ddi() {
    local outdir="${1:?}"
    local container_name="${2:?}"

    cat >"$outdir"/openssl.conf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = DE
ST = Test State
L = Test Locality
O = Org Name
OU = Org Unit Name
CN = Common Name
emailAddress = test@email.com
EOF

    openssl req -config "$outdir"/openssl.conf -subj="/CN=waldo" \
            -x509 -sha256 -nodes -days 365 -newkey rsa:4096 \
            -keyout "${outdir}/${container_name}.key" -out "${outdir}/${container_name}.crt"

    mkdir -p /run/verity.d
    cp "${outdir}/${container_name}.crt" "/run/verity.d/test-13-nspawn-${container_name}.crt"

    SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs \
        systemd-repart --make-ddi=portable \
                       --copy-source=/usr/share/TEST-13-NSPAWN-container-template \
                       --certificate="${outdir}/${container_name}.crt" \
                       --private-key="${outdir}/${container_name}.key" \
                       "${outdir}/${container_name}.raw"
}

testcase_unpriv() {
    if ! can_do_rootless_nspawn; then
        echo "Skipping rootless test..."
        return 0
    fi

    local tmpdir name
    tmpdir="$(mktemp -d /var/tmp/TEST-13-NSPAWN.unpriv.XXX)"
    # Note: we pick the machine name short enough to be a valid machine name,
    # but definitely longer than 16 chars, so that userns name mangling in the
    # nsresourced userns allocation logic is triggered and tested. */
    name="unprv-${tmpdir##*.}-somelongsuffix"
    trap 'rm -fr ${tmpdir@Q} || true; rm -f /run/verity.d/test-13-nspawn-${name@Q} || true' RETURN ERR
    create_dummy_ddi "$tmpdir" "$name"
    chown --recursive testuser: "$tmpdir"

    run0 --pipe -u testuser systemd-run \
        --user \
        --pipe \
        --property=Delegate=yes \
        -- \
        systemd-nspawn --pipe --private-network --register=no --keep-unit --image="$tmpdir/$name.raw" echo hello >"$tmpdir/stdout.txt"
    echo hello | cmp "$tmpdir/stdout.txt" -

    # Make sure per-user search path logic works
    run0 -u testuser --pipe mkdir -p /home/testuser/.local/state/machines
    run0 -u testuser --pipe ln -s "$tmpdir/$name.raw" /home/testuser/.local/state/machines/"x$name.raw"
    run0 --pipe -u testuser systemd-run \
        --user \
        --pipe \
        --property=Delegate=yes \
        -- \
        systemd-nspawn --pipe --private-network --register=no --keep-unit --machine="x$name" echo hello >"$tmpdir/stdout.txt"
    echo hello | cmp "$tmpdir/stdout.txt" -
}

testcase_fuse() {
    if [[ "$(cat <>/dev/fuse 2>&1)" != 'cat: -: Operation not permitted' ]]; then
        echo "FUSE is not supported, skipping the test..."
        return 0
    fi

    # Assume that the tests are running on a kernel that is new enough for FUSE
    # to have user-namespace support; and so we should expect that nspawn
    # enables FUSE.  This test does not validate that the version check
    # disables FUSE on old kernels.

    local root

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.fuse.XXX)"
    create_dummy_container "$root"

    # To avoid adding any complex dependencies to the test, we simply check
    # that /dev/fuse can be opened for reading and writing (O_RDWR), but that
    # actually reading from it fails with EPERM.  This can be done with a
    # simple Bash script: run `cat <>/dev/fuse` and if the EPERM error message
    # comes from "bash" then we know it couldn't be opened, while if it comes
    # from "cat" then we know that it was opened but not read.  If we are able
    # to read from the file, then this indicates that it's not a real FUSE
    # device (which requires us to mount a type="fuse" filesystem with the
    # option string "fd=${num}" for /dev/fuse FD before reading from it will
    # return anything other than EPERM); if this happens then most likely
    # nspawn didn't create the file at all and Bash "<>" simply created a new
    # normal file.
    #
    #    "cat: -: Operation not permitted"                   # pass the test; opened but not read
    #    "bash: line 1: /dev/fuse: Operation not permitted"  # fail the test; could not open
    #    ""                                                  # fail the test; reading worked
    [[ "$(systemd-nspawn --register=no --pipe --directory="$root" \
              bash -c 'cat <>/dev/fuse' 2>&1)" == 'cat: -: Operation not permitted' ]]

    rm -fr "$root"
}

testcase_unpriv_fuse() {
    # Same as above, but for unprivileged operation.

    if [[ "$(cat <>/dev/fuse 2>&1)" != 'cat: -: Operation not permitted' ]]; then
        echo "FUSE is not supported, skipping the test..."
        return 0
    fi
    if ! can_do_rootless_nspawn; then
        echo "Skipping rootless test..."
        return 0
    fi

    local tmpdir name
    tmpdir="$(mktemp -d /var/tmp/TEST-13-NSPAWN.unpriv-fuse.XXX)"
    # $name must be such that len("ns-$(id -u testuser)-nspawn-${name}-65535")
    # <= 31, or nsresourced will reject the request for a namespace.
    # Therefore; len($name) <= 10 bytes.
    name="ufuse-${tmpdir##*.}"
    trap 'rm -fr ${tmpdir@Q} || true; rm -f /run/verity.d/test-13-nspawn-${name@Q} || true' RETURN ERR
    create_dummy_ddi "$tmpdir" "$name"
    chown --recursive testuser: "$tmpdir"

    [[ "$(run0 -u testuser --pipe systemd-run \
              --user \
              --pipe \
              --property=Delegate=yes \
              --setenv=SYSTEMD_LOG_LEVEL \
              --setenv=SYSTEMD_LOG_TARGET \
              -- \
              systemd-nspawn --pipe --private-network --register=no --keep-unit --image="$tmpdir/$name.raw" \
                  bash -c 'cat <>/dev/fuse' 2>&1)" == *'cat: -: Operation not permitted' ]]
}

test_tun() {
    systemd-nspawn --register=no "$@" bash -xec '[[ -c /dev/net/tun ]]; [[ "$(stat /dev/net/tun --format=%u)" == 0 ]]; [[ "$(stat /dev/net/tun --format=%g)" == 0 ]]'

    # check if the owner of the host device is unchanged, see issue #34243.
    [[ "$(stat /dev/net/tun --format=%u)" == 0 ]]
    [[ "$(stat /dev/net/tun --format=%g)" == 0 ]]

    # Without DeviceAllow= for /dev/net/tun, see issue #35116.
    systemd-run \
        --wait -p Environment=SYSTEMD_LOG_LEVEL=debug -p DevicePolicy=closed -p DeviceAllow="char-pts rw" \
        systemd-nspawn --register=no "$@" bash -xec '[[ ! -e /dev/net/tun ]]'

    [[ "$(stat /dev/net/tun --format=%u)" == 0 ]]
    [[ "$(stat /dev/net/tun --format=%g)" == 0 ]]
}

testcase_dev_net_tun() {
    local root

    if [[ ! -c /dev/net/tun ]]; then
        echo "/dev/net/tun does not exist, skipping tests"
        return 0
    fi

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.tun.XXX)"
    create_dummy_container "$root"

    test_tun --ephemeral --directory="$root" --private-users=no
    test_tun --ephemeral --directory="$root" --private-users=yes
    test_tun --ephemeral --directory="$root" --private-users=pick
    test_tun --ephemeral --directory="$root" --private-users=no   --private-network
    test_tun --ephemeral --directory="$root" --private-users=yes  --private-network
    test_tun --ephemeral --directory="$root" --private-users=pick --private-network

    rm -fr "$root"
}

testcase_unpriv_dir() {
    if ! can_do_rootless_nspawn; then
        echo "Skipping rootless test..."
        return 0
    fi

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.unpriv.XXX)"
    create_dummy_container "$root"

    assert_eq "$(systemd-nspawn --pipe --register=no -D "$root" --private-users=no bash -c 'echo foobar')" "foobar"

    # Use an image owned by some freshly acquired container user
    assert_eq "$(systemd-nspawn --pipe --register=no -D "$root" --private-users=pick --private-users-ownership=chown bash -c 'echo foobar')" "foobar"
    assert_eq "$(systemd-nspawn --pipe --register=no -D "$root" --private-users=yes --private-users-ownership=chown bash -c 'echo foobar')" "foobar"

    # Now move back to root owned, and try to use fs idmapping
    systemd-dissect --shift "$root" 0
    assert_eq "$(systemd-nspawn --pipe --register=no -D "$root" --private-users=no --private-users-ownership=no bash -c 'echo foobar')" "foobar"
    assert_eq "$(systemd-nspawn --pipe --register=no -D "$root" --private-users=pick --private-users-ownership=map bash -c 'echo foobar')" "foobar"

    # Use an image owned by the foreign UID range first via direct mapping, and than via the managed uid logic
    systemd-dissect --shift "$root" foreign
    assert_eq "$(systemd-nspawn --pipe --register=no -D "$root" --private-users=pick --private-users-ownership=foreign bash -c 'echo foobar')" "foobar"
    assert_eq "$(systemd-nspawn --pipe --register=no -D "$root" --private-users=managed --private-network bash -c 'echo foobar')" "foobar"

    # Test unprivileged operation
    chown testuser:testuser "$root/.."

    ls -al "/var/lib/machines"
    ls -al "$root"

    assert_eq "$(run0 --pipe -u testuser systemd-nspawn --pipe --register=no -D "$root" --private-users=managed --private-network bash -c 'echo foobar')" "foobar"
    assert_eq "$(run0 --pipe -u testuser systemd-nspawn --pipe --register=no -D "$root" --private-network bash -c 'echo foobar')" "foobar"
    chown root:root "$root/.."

    rm -rf "$root"
}

testcase_link_journal_host() {
    local root hoge i

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.link-journal.XXX)"
    create_dummy_container "$root"

    systemd-id128 new > "$root"/etc/machine-id

    hoge="/var/log/journal/$(cat "$root"/etc/machine-id)/"
    mkdir -p "$hoge"
    # The systemd-journal group is not mapped, so ensure the directory is owned by root:root
    chown root:root "$hoge"

    for i in no yes pick; do
        systemd-nspawn \
            --register=no --directory="$root" --private-users="$i" --link-journal=host \
            bash -xec 'p="/var/log/journal/$(cat /etc/machine-id)"; mountpoint "$p"; [[ "$(stat "$p" --format=%u)" == 0 ]]; touch "$p/hoge"'

        [[ "$(stat "${hoge}/hoge" --format=%u)" == 0 ]]
        rm "${hoge}/hoge"
    done

    rm -fr "$root" "$hoge"
}

testcase_volatile_link_journal_no_userns() {
    local root machine_id journal_dir acl_output

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.volatile-journal.XXX)"
    create_dummy_container "$root"

    machine_id="$(systemd-id128 new)"
    echo "$machine_id" >"$root/etc/machine-id"

    journal_dir="/var/log/journal/$machine_id"
    mkdir -p "$journal_dir"
    chown root:root "$journal_dir"

    systemd-nspawn --register=no \
                   --directory="$root" \
                   --boot \
                   --volatile=yes \
                   --link-journal=host \
                   systemd.unit=systemd-tmpfiles-setup.service

    local gid
    gid="$(stat -c '%g' "$journal_dir")"

    # Ensure GID is not 4294967295 (GID_INVALID)
    [[ "$gid" != "4294967295" ]]

    # Ensure the directory is owned by a valid user (root or systemd-journal
    # group). The GID should be either 0 (root) or the systemd-journal GID, not
    # some bombastically large number
    [[ "$gid" -lt 65535 ]]

    # Ensure the invalid GID doesn't appear in ACLs
    acl_output="$(getfacl "$journal_dir" || true)"
    grep -q "4294967295" <<< "$acl_output" && exit 1

    rm -fr "$root" "$journal_dir"
}

testcase_cap_net_bind_service() {
    local root

    root="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.cap-net-bind-service.XXX)"
    create_dummy_container "$root"

    # Check that CAP_NET_BIND_SERVICE is available without --private-users
    systemd-nspawn --register=no --directory="$root" capsh --has-p=cap_net_bind_service

    # Check that CAP_NET_BIND_SERVICE is not available with --private-users=identity
    (! systemd-nspawn --register=no --directory="$root" --private-users=identity capsh --has-p=cap_net_bind_service)

    # Check that CAP_NET_BIND_SERVICE is not available with --private-users=pick
    (! systemd-nspawn --register=no --directory="$root" --private-users=pick capsh --has-p=cap_net_bind_service)

    rm -fr "$root"
}

run_testcases
