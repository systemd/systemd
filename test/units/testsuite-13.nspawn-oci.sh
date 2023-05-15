#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug
export SYSTEMD_LOG_TARGET=journal
CREATE_BB_CONTAINER="/usr/lib/systemd/tests/testdata/create-busybox-container"

# shellcheck disable=SC2317
at_exit() {
    set +e

    mountpoint -q /var/lib/machines && umount /var/lib/machines
    [[ -n "${DEV:-}" ]] && rm -f "$DEV"
    [[ -n "${NETNS:-}" ]] && umount "$NETNS" && rm -f "$NETNS"
    [[ -n "${TMPDIR:-}" ]] && rm -fr "$TMPDIR"
}

trap at_exit EXIT

# Mount tmpfs over /var/lib/machines to not pollute the image
mkdir -p /var/lib/machines
mount -t tmpfs tmpfs /var/lib/machines

# Setup a couple of dirs/devices for the OCI containers
DEV="$(mktemp -u /dev/oci-dev-XXX)"
mknod -m 666 "$DEV" b 42 42
NETNS="$(mktemp /var/tmp/netns.XXX)"
mount --bind /proc/self/ns/net "$NETNS"
TMPDIR="$(mktemp -d)"
touch "$TMPDIR/hello"
OCI="$(mktemp -d /var/lib/machines/testsuite-13.oci-bundle.XXX)"
"$CREATE_BB_CONTAINER" "$OCI/rootfs"
mkdir -p "$OCI/rootfs/opt/var"
mkdir -p "$OCI/rootfs/opt/readonly"

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
systemd-nspawn --oci-bundle="$OCI" sh -xec 'mountpoint /root'

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
            "sh",
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
#!/bin/sh

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
test -e /proc/kcore
cat /proc/kcore && exit 1
test ! -e /root/nonexistent

# Linux - readonlyPaths
touch /opt/readonly/foo && exit 1

exit 0
EOF
systemd-nspawn --oci-bundle="$OCI"
