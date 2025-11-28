#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_LOG_TARGET=journal

# shellcheck disable=SC2317
at_exit() {
    set +e

    mountpoint -q /var/lib/machines && umount /var/lib/machines
    [[ -n "${DEV:-}" ]] && rm -f "$DEV"
    [[ -n "${NETNS:-}" ]] && umount "$NETNS" && rm -f "$NETNS"
    [[ -n "${TMPDIR:-}" ]] && rm -fr "$TMPDIR"
    rm -f /run/systemd/nspawn/*.nspawn
}

trap at_exit EXIT

# Mount temporary directory over /var/lib/machines to not pollute the image
mkdir -p /var/lib/machines
mount --bind "$(mktemp --tmpdir=/var/tmp -d)" /var/lib/machines

# Setup a couple of dirs/devices for the OCI containers
DEV="$(mktemp -u /dev/oci-dev-XXX)"
mknod -m 666 "$DEV" b 42 42
NETNS="$(mktemp /var/tmp/netns.XXX)"
mount --bind /proc/self/ns/net "$NETNS"
TMPDIR="$(mktemp -d)"
touch "$TMPDIR/hello"
OCI="$(mktemp -d /var/lib/machines/TEST-13-NSPAWN.oci-bundle.XXX)"
create_dummy_container "$OCI/rootfs"
mkdir -p "$OCI/rootfs/opt/var"
mkdir -p "$OCI/rootfs/opt/readonly"

if [[ -e /proc/kcore ]]; then
    HAVE_PROC_KCORE=1
else
    HAVE_PROC_KCORE=0
fi

# Let's start with a simple config
cat >"$OCI/config.json" <<EOF
{
    "ociVersion" : "1.0.0",
    "root" : {
            "path" : "rootfs"
    },
    "mounts" : [
        {
            "destination" : "/root",
            "type" : "tmpfs",
            "source" : "tmpfs"
        }
    ]
}
EOF
systemd-nspawn --oci-bundle="$OCI" bash -xec 'mountpoint /root'

# And now for something a bit more involved
# Notes:
#   - the hooks are parsed & processed, but never executed
#   - set sysctl's are parsed but never used?
#       - same goes for arg_sysctl in nspawn.c
cat >"$OCI/config.json" <<EOF
{
    "ociVersion" : "1.0.0",
    "hostname" : "my-oci-container",
    "root" : {
            "path" : "rootfs",
            "readonly" : false
    },
    "mounts" : [
        {
            "destination" : "/root",
            "type" : "tmpfs",
            "source" : "tmpfs"
        },
        ${COVERAGE_BUILD_DIR:+"{ \"destination\" : \"$COVERAGE_BUILD_DIR\" },"}
        {
            "destination" : "/var",
            "type" : "none",
            "source" : "$TMPDIR",
            "options" : ["rbind", "rw"]
        }
    ],
    "process" : {
        "terminal" : false,
        "consoleSize" : {
            "height" : 25,
            "width" : 80
        },
        "user" : {
            "uid" : 0,
            "gid" : 0,
            "additionalGids" : [5, 6]
        },
        "env" : [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "FOO=bar"
        ],
        "cwd" : "/root",
        "args" : [
            "bash",
            "-xe",
            "/entrypoint.sh"
        ],
        "noNewPrivileges" : true,
        "oomScoreAdj" : 20,
        "capabilities" : {
            "bounding" : [
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            ],
            "permitted" : [
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            ],
            "inheritable" : [
                "CAP_AUDIT_WRITE",
                "CAP_KILL",
                "CAP_NET_BIND_SERVICE"
            ],
            "effective" : [
                "CAP_AUDIT_WRITE",
                "CAP_KILL"
            ],
            "ambient" : [
                "CAP_NET_BIND_SERVICE"
            ]
        },
        "rlimits" : [
            {
                "type" : "RLIMIT_NOFILE",
                "soft" : 1024,
                "hard" : 1024
            },
            {
                "type" : "RLIMIT_RTPRIO",
                "soft" : 5,
                "hard" : 10
            }
        ]
    },
    "linux" : {
        "namespaces" : [
            {
                "type" : "mount"
            },
            {
                "type" : "network",
                "path" : "$NETNS"
            },
            {
                "type" : "pid"
            },
            {
                "type" : "uts"
            }
        ],
        "uidMappings" : [
            {
                "containerID" : 0,
                "hostID" : 1000,
                "size" : 100
            }
        ],
        "gidMappings" : [
            {
                "containerID" : 0,
                "hostID" : 1000,
                "size" : 100
            }
        ],
        "devices" : [
            {
                "type" : "c",
                "path" : "/dev/zero",
                "major" : 1,
                "minor" : 5,
                "fileMode" : 444
            },
            {
                "type" : "b",
                "path" : "$DEV",
                "major" : 4,
                "minor" : 2,
                "fileMode" : 666,
                "uid" : 0,
                "gid" : 0
            }
        ],
        "resources" : {
            "devices" : [
                {
                    "allow" : false,
                    "access" : "m"
                },
                {
                    "allow" : true,
                    "type" : "b",
                    "major" : 4,
                    "minor" : 2,
                    "access" : "rwm"
                }
            ],
            "memory" : {
                "limit" : 134217728,
                "reservation" : 33554432,
                "swap" : 268435456
            },
            "cpu" : {
                "shares" : 1024,
                "quota" : 1000000,
                "period" : 500000,
                "cpus" : "0-7"
            },
            "blockIO" : {
                "weight" : 10,
                "weightDevice" : [
                    {
                        "major" : 4,
                        "minor" : 2,
                        "weight" : 500
                    }
                ],
                "throttleReadBpsDevice" : [
                    {
                        "major" : 4,
                        "minor" : 2,
                        "rate" : 500
                    }
                ],
                "throttleWriteBpsDevice" : [
                    {
                        "major" : 4,
                        "minor" : 2,
                        "rate" : 500
                    }
                ],
                "throttleReadIOPSDevice" : [
                    {
                        "major" : 4,
                        "minor" : 2,
                        "rate" : 500
                    }
                ],
                "throttleWriteIOPSDevice" : [
                    {
                        "major" : 4,
                        "minor" : 2,
                        "rate" : 500
                    }
                ]
            },
            "pids" : {
                "limit" : 1024
            }
        },
        "sysctl" : {
            "kernel.domainname" : "foo.bar",
            "vm.swappiness" : "60"
        },
        "seccomp" : {
            "defaultAction" : "SCMP_ACT_ALLOW",
            "architectures" : [
                "SCMP_ARCH_ARM",
                "SCMP_ARCH_X86_64"
            ],
            "syscalls" : [
                {
                    "names" : [
                        "lchown",
                        "chmod"
                    ],
                    "action" : "SCMP_ACT_ERRNO",
                    "args" : [
                        {
                            "index" : 0,
                            "value" : 1,
                            "op" : "SCMP_CMP_NE"
                        },
                        {
                            "index" : 1,
                            "value" : 2,
                            "valueTwo" : 3,
                            "op" : "SCMP_CMP_MASKED_EQ"
                        }
                    ]
                }
            ]
        },
        "rootfsPropagation" : "shared",
        "maskedPaths" : [
            "/proc/kcore",
            "/root/nonexistent"
        ],
        "readonlyPaths" : [
            "/proc/sys",
            "/opt/readonly"
        ]
    },
    "hooks" : {
        "prestart" : [
            {
                "path" : "/bin/sh",
                "args" : [
                    "-xec",
                    "echo \$PRESTART_FOO >/prestart"
                ],
                "env" : [
                    "PRESTART_FOO=prestart_bar",
                    "ALSO_FOO=also_bar"
                ],
                "timeout" : 666
            },
            {
                "path" : "/bin/touch",
                "args" : [
                    "/tmp/also-prestart"
                ]
            }
        ],
        "poststart" : [
            {
                "path" : "/bin/sh",
                "args" : [
                    "touch",
                    "/poststart"
                ]
            }
        ],
        "poststop" : [
            {
                "path" : "/bin/sh",
                "args" : [
                    "touch",
                    "/poststop"
                ]
            }
        ]
    },
    "annotations" : {
        "hello.world" : "1",
        "foo" : "bar"
    }
}
EOF
# Create a simple "entrypoint" script that validates that the container
# is created correctly according to the OCI config
cat >"$OCI/rootfs/entrypoint.sh" <<EOF
#!/usr/bin/env bash
set -e

# Mounts
mountpoint /root
mountpoint /var
test -e /var/hello

# Process
[[ "\$PWD" == /root ]]
[[ "\$FOO" == bar ]]

# Process - rlimits
[[ "\$(ulimit -S -n)" -eq 1024 ]]
[[ "\$(ulimit -H -n)" -eq 1024 ]]
[[ "\$(ulimit -S -r)" -eq 5 ]]
[[ "\$(ulimit -H -r)" -eq 10 ]]
[[ "\$(hostname)" == my-oci-container ]]

# Linux - devices
test -c /dev/zero
test -b "$DEV"
[[ "\$(stat -c '%t:%T' "$DEV")" == 4:2 ]]

# Linux - maskedPaths
if [[ "$HAVE_PROC_KCORE" == 1 ]]; then
    test -e /proc/kcore
    cat /proc/kcore && exit 1
else
    test ! -e /proc/kcore
fi
test ! -e /root/nonexistent

# Linux - readonlyPaths
touch /opt/readonly/foo && exit 1

exit 0
EOF
timeout 30 systemd-nspawn --oci-bundle="$OCI"

# Test a couple of invalid configs
INVALID_SNIPPETS=(
    # Invalid object
    '"foo" : { }'
    '"process" : { "foo" : [ ] }'
    # Non-absolute mount
    '"mounts" : [ { "destination" : "foo", "type" : "tmpfs", "source" : "tmpfs" } ]'
    # Invalid rlimit
    '"process" : { "rlimits" : [ { "type" : "RLIMIT_FOO", "soft" : 0, "hard" : 0 } ] }'
    # rlimit without RLIMIT_ prefix
    '"process" : { "rlimits" : [ { "type" : "CORE", "soft" : 0, "hard" : 0 } ] }'
    # Invalid env assignment
    '"process" : { "env" : [ "foo" ] }'
    '"process" : { "env" : [ "foo=bar", 1 ] }'
    # Invalid process args
    '"process" : { "args" : [ ] }'
    '"process" : { "args" : [ "" ] }'
    '"process" : { "args" : [ "foo", 1 ] }'
    # Invalid capabilities
    '"process" : { "capabilities" : { "bounding" : [ 1 ] } }'
    '"process" : { "capabilities" : { "bounding" : [ "FOO_BAR" ] } }'
    # Unsupported option (without JSON_PERMISSIVE)
    '"linux" : { "resources" : { "cpu" : { "realtimeRuntime" : 1 } } }'
    # Invalid namespace
    '"linux" : { "namespaces" : [ { "type" : "foo" } ] }'
    # Namespace path for a non-network namespace
    '"linux" : { "namespaces" : [ { "type" : "user", "path" : "/foo/bar" } ] }'
    # Duplicate namespace
    '"linux" : { "namespaces" : [ { "type" : "ipc" }, { "type" : "ipc" } ] }'
    # Invalid device type
    '"linux" : { "devices" : [ { "type" : "foo", "path" : "/dev/foo" } ] }'
    # Invalid cgroups path
    '"linux" : { "cgroupsPath" : "/foo/bar/baz" }'
    '"linux" : { "cgroupsPath" : "foo/bar/baz" }'
    # Invalid sysctl assignments
    '"linux" : { "sysctl" : { "vm.swappiness" : 60 } }'
    '"linux" : { "sysctl" : { "foo..bar" : "baz" } }'
    # Invalid seccomp assignments
    '"linux" : { "seccomp" : { } }'
    '"linux" : { "seccomp" : { "defaultAction" : 1 } }'
    '"linux" : { "seccomp" : { "defaultAction" : "foo" } }'
    '"linux" : { "seccomp" : { "defaultAction" : "SCMP_ACT_ALLOW", "syscalls" : [ { "action" : "SCMP_ACT_ERRNO", "names" : [ ] } ] } }'
    # Invalid masked paths
    '"linux" : { "maskedPaths" : [ "/foo", 1 ] }'
    '"linux" : { "maskedPaths" : [ "/foo", "bar" ] }'
    # Invalid read-only paths
    '"linux" : { "readonlyPaths" : [ "/foo", 1 ] }'
    '"linux" : { "readonlyPaths" : [ "/foo", "bar" ] }'
    # Invalid hooks
    '"hooks" : { "prestart" : [ { "path" : "/bin/sh", "timeout" : 0 } ] }'
    # Invalid annotations
    '"annotations" : { "" : "bar" }'
    '"annotations" : { "foo" : 1 }'
)

for snippet in "${INVALID_SNIPPETS[@]}"; do
    : "Snippet: $snippet"
    cat >"$OCI/config.json" <<EOF
{
    "ociVersion" : "1.0.0",
    "root" : {
            "path" : "rootfs"
    },
    $snippet
}
EOF
    (! systemd-nspawn --oci-bundle="$OCI" sh -c 'echo hello')
done

# Invalid OCI bundle version
cat >"$OCI/config.json" <<EOF
{
    "ociVersion" : "6.6.6",
    "root" : {
            "path" : "rootfs"
    }
}
EOF
(! systemd-nspawn --oci-bundle="$OCI" sh -c 'echo hello')
