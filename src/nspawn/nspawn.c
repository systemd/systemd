/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/prctl.h>
#include <getopt.h>
#include <grp.h>
#include <linux/fs.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <linux/veth.h>
#include <sys/personality.h>
#include <linux/loop.h>
#include <sys/file.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

#ifdef HAVE_BLKID
#include <blkid/blkid.h>
#endif

#include "random-util.h"
#include "sd-daemon.h"
#include "sd-bus.h"
#include "sd-id128.h"
#include "sd-rtnl.h"
#include "log.h"
#include "util.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "macro.h"
#include "missing.h"
#include "cgroup-util.h"
#include "strv.h"
#include "path-util.h"
#include "loopback-setup.h"
#include "dev-setup.h"
#include "fdset.h"
#include "build.h"
#include "fileio.h"
#include "bus-util.h"
#include "bus-error.h"
#include "ptyfwd.h"
#include "env-util.h"
#include "rtnl-util.h"
#include "udev-util.h"
#include "blkid-util.h"
#include "gpt.h"
#include "siphash24.h"
#include "copy.h"
#include "base-filesystem.h"
#include "barrier.h"
#include "event-util.h"
#include "capability.h"
#include "cap-list.h"
#include "btrfs-util.h"
#include "machine-image.h"
#include "list.h"
#include "in-addr-util.h"
#include "fw-util.h"
#include "local-addresses.h"
#include "formats-util.h"
#include "process-util.h"
#include "terminal-util.h"

#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#endif

typedef struct ExposePort {
        int protocol;
        uint16_t host_port;
        uint16_t container_port;
        LIST_FIELDS(struct ExposePort, ports);
} ExposePort;

typedef enum ContainerStatus {
        CONTAINER_TERMINATED,
        CONTAINER_REBOOTED
} ContainerStatus;

typedef enum LinkJournal {
        LINK_NO,
        LINK_AUTO,
        LINK_HOST,
        LINK_GUEST
} LinkJournal;

typedef enum Volatile {
        VOLATILE_NO,
        VOLATILE_YES,
        VOLATILE_STATE,
} Volatile;

static char *arg_directory = NULL;
static char *arg_template = NULL;
static char *arg_user = NULL;
static sd_id128_t arg_uuid = {};
static char *arg_machine = NULL;
static const char *arg_selinux_context = NULL;
static const char *arg_selinux_apifs_context = NULL;
static const char *arg_slice = NULL;
static bool arg_private_network = false;
static bool arg_read_only = false;
static bool arg_boot = false;
static bool arg_ephemeral = false;
static LinkJournal arg_link_journal = LINK_AUTO;
static bool arg_link_journal_try = false;
static uint64_t arg_retain =
        (1ULL << CAP_CHOWN) |
        (1ULL << CAP_DAC_OVERRIDE) |
        (1ULL << CAP_DAC_READ_SEARCH) |
        (1ULL << CAP_FOWNER) |
        (1ULL << CAP_FSETID) |
        (1ULL << CAP_IPC_OWNER) |
        (1ULL << CAP_KILL) |
        (1ULL << CAP_LEASE) |
        (1ULL << CAP_LINUX_IMMUTABLE) |
        (1ULL << CAP_NET_BIND_SERVICE) |
        (1ULL << CAP_NET_BROADCAST) |
        (1ULL << CAP_NET_RAW) |
        (1ULL << CAP_SETGID) |
        (1ULL << CAP_SETFCAP) |
        (1ULL << CAP_SETPCAP) |
        (1ULL << CAP_SETUID) |
        (1ULL << CAP_SYS_ADMIN) |
        (1ULL << CAP_SYS_CHROOT) |
        (1ULL << CAP_SYS_NICE) |
        (1ULL << CAP_SYS_PTRACE) |
        (1ULL << CAP_SYS_TTY_CONFIG) |
        (1ULL << CAP_SYS_RESOURCE) |
        (1ULL << CAP_SYS_BOOT) |
        (1ULL << CAP_AUDIT_WRITE) |
        (1ULL << CAP_AUDIT_CONTROL) |
        (1ULL << CAP_MKNOD);
static char **arg_bind = NULL;
static char **arg_bind_ro = NULL;
static char **arg_tmpfs = NULL;
static char **arg_setenv = NULL;
static bool arg_quiet = false;
static bool arg_share_system = false;
static bool arg_register = true;
static bool arg_keep_unit = false;
static char **arg_network_interfaces = NULL;
static char **arg_network_macvlan = NULL;
static char **arg_network_ipvlan = NULL;
static bool arg_network_veth = false;
static const char *arg_network_bridge = NULL;
static unsigned long arg_personality = 0xffffffffLU;
static char *arg_image = NULL;
static Volatile arg_volatile = VOLATILE_NO;
static ExposePort *arg_expose_ports = NULL;
static char **arg_property = NULL;
static uid_t arg_uid_shift = UID_INVALID, arg_uid_range = 0x10000U;
static bool arg_userns = false;
static int arg_kill_signal = 0;

static void help(void) {
        printf("%s [OPTIONS...] [PATH] [ARGUMENTS...]\n\n"
               "Spawn a minimal namespace container for debugging, testing and building.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "  -q --quiet                Do not show status information\n"
               "  -D --directory=PATH       Root directory for the container\n"
               "     --template=PATH        Initialize root directory from template directory,\n"
               "                            if missing\n"
               "  -x --ephemeral            Run container with snapshot of root directory, and\n"
               "                            remove it after exit\n"
               "  -i --image=PATH           File system device or disk image for the container\n"
               "  -b --boot                 Boot up full system (i.e. invoke init)\n"
               "  -u --user=USER            Run the command under specified user or uid\n"
               "  -M --machine=NAME         Set the machine name for the container\n"
               "     --uuid=UUID            Set a specific machine UUID for the container\n"
               "  -S --slice=SLICE          Place the container in the specified slice\n"
               "     --property=NAME=VALUE  Set scope unit property\n"
               "     --private-network      Disable network in container\n"
               "     --network-interface=INTERFACE\n"
               "                            Assign an existing network interface to the\n"
               "                            container\n"
               "     --network-macvlan=INTERFACE\n"
               "                            Create a macvlan network interface based on an\n"
               "                            existing network interface to the container\n"
               "     --network-ipvlan=INTERFACE\n"
               "                            Create a ipvlan network interface based on an\n"
               "                            existing network interface to the container\n"
               "  -n --network-veth         Add a virtual ethernet connection between host\n"
               "                            and container\n"
               "     --network-bridge=INTERFACE\n"
               "                            Add a virtual ethernet connection between host\n"
               "                            and container and add it to an existing bridge on\n"
               "                            the host\n"
               "     --private-users[=UIDBASE[:NUIDS]]\n"
               "                            Run within user namespace\n"
               "  -p --port=[PROTOCOL:]HOSTPORT[:CONTAINERPORT]\n"
               "                            Expose a container IP port on the host\n"
               "  -Z --selinux-context=SECLABEL\n"
               "                            Set the SELinux security context to be used by\n"
               "                            processes in the container\n"
               "  -L --selinux-apifs-context=SECLABEL\n"
               "                            Set the SELinux security context to be used by\n"
               "                            API/tmpfs file systems in the container\n"
               "     --capability=CAP       In addition to the default, retain specified\n"
               "                            capability\n"
               "     --drop-capability=CAP  Drop the specified capability from the default set\n"
               "     --kill-signal=SIGNAL   Select signal to use for shutting down PID 1\n"
               "     --link-journal=MODE    Link up guest journal, one of no, auto, guest, host,\n"
               "                            try-guest, try-host\n"
               "  -j                        Equivalent to --link-journal=try-guest\n"
               "     --read-only            Mount the root directory read-only\n"
               "     --bind=PATH[:PATH]     Bind mount a file or directory from the host into\n"
               "                            the container\n"
               "     --bind-ro=PATH[:PATH]  Similar, but creates a read-only bind mount\n"
               "     --tmpfs=PATH:[OPTIONS] Mount an empty tmpfs to the specified directory\n"
               "     --setenv=NAME=VALUE    Pass an environment variable to PID 1\n"
               "     --share-system         Share system namespaces with host\n"
               "     --register=BOOLEAN     Register container as machine\n"
               "     --keep-unit            Do not register a scope for the machine, reuse\n"
               "                            the service unit nspawn is running in\n"
               "     --volatile[=MODE]      Run the system in volatile mode\n"
               , program_invocation_short_name);
}

static int set_sanitized_path(char **b, const char *path) {
        char *p;

        assert(b);
        assert(path);

        p = canonicalize_file_name(path);
        if (!p) {
                if (errno != ENOENT)
                        return -errno;

                p = path_make_absolute_cwd(path);
                if (!p)
                        return -ENOMEM;
        }

        free(*b);
        *b = path_kill_slashes(p);
        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_PRIVATE_NETWORK,
                ARG_UUID,
                ARG_READ_ONLY,
                ARG_CAPABILITY,
                ARG_DROP_CAPABILITY,
                ARG_LINK_JOURNAL,
                ARG_BIND,
                ARG_BIND_RO,
                ARG_TMPFS,
                ARG_SETENV,
                ARG_SHARE_SYSTEM,
                ARG_REGISTER,
                ARG_KEEP_UNIT,
                ARG_NETWORK_INTERFACE,
                ARG_NETWORK_MACVLAN,
                ARG_NETWORK_IPVLAN,
                ARG_NETWORK_BRIDGE,
                ARG_PERSONALITY,
                ARG_VOLATILE,
                ARG_TEMPLATE,
                ARG_PROPERTY,
                ARG_PRIVATE_USERS,
                ARG_KILL_SIGNAL,
        };

        static const struct option options[] = {
                { "help",                  no_argument,       NULL, 'h'                   },
                { "version",               no_argument,       NULL, ARG_VERSION           },
                { "directory",             required_argument, NULL, 'D'                   },
                { "template",              required_argument, NULL, ARG_TEMPLATE          },
                { "ephemeral",             no_argument,       NULL, 'x'                   },
                { "user",                  required_argument, NULL, 'u'                   },
                { "private-network",       no_argument,       NULL, ARG_PRIVATE_NETWORK   },
                { "boot",                  no_argument,       NULL, 'b'                   },
                { "uuid",                  required_argument, NULL, ARG_UUID              },
                { "read-only",             no_argument,       NULL, ARG_READ_ONLY         },
                { "capability",            required_argument, NULL, ARG_CAPABILITY        },
                { "drop-capability",       required_argument, NULL, ARG_DROP_CAPABILITY   },
                { "link-journal",          required_argument, NULL, ARG_LINK_JOURNAL      },
                { "bind",                  required_argument, NULL, ARG_BIND              },
                { "bind-ro",               required_argument, NULL, ARG_BIND_RO           },
                { "tmpfs",                 required_argument, NULL, ARG_TMPFS             },
                { "machine",               required_argument, NULL, 'M'                   },
                { "slice",                 required_argument, NULL, 'S'                   },
                { "setenv",                required_argument, NULL, ARG_SETENV            },
                { "selinux-context",       required_argument, NULL, 'Z'                   },
                { "selinux-apifs-context", required_argument, NULL, 'L'                   },
                { "quiet",                 no_argument,       NULL, 'q'                   },
                { "share-system",          no_argument,       NULL, ARG_SHARE_SYSTEM      },
                { "register",              required_argument, NULL, ARG_REGISTER          },
                { "keep-unit",             no_argument,       NULL, ARG_KEEP_UNIT         },
                { "network-interface",     required_argument, NULL, ARG_NETWORK_INTERFACE },
                { "network-macvlan",       required_argument, NULL, ARG_NETWORK_MACVLAN   },
                { "network-ipvlan",        required_argument, NULL, ARG_NETWORK_IPVLAN    },
                { "network-veth",          no_argument,       NULL, 'n'                   },
                { "network-bridge",        required_argument, NULL, ARG_NETWORK_BRIDGE    },
                { "personality",           required_argument, NULL, ARG_PERSONALITY       },
                { "image",                 required_argument, NULL, 'i'                   },
                { "volatile",              optional_argument, NULL, ARG_VOLATILE          },
                { "port",                  required_argument, NULL, 'p'                   },
                { "property",              required_argument, NULL, ARG_PROPERTY          },
                { "private-users",         optional_argument, NULL, ARG_PRIVATE_USERS     },
                { "kill-signal",           required_argument, NULL, ARG_KILL_SIGNAL       },
                {}
        };

        int c, r;
        uint64_t plus = 0, minus = 0;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hD:u:bL:M:jS:Z:qi:xp:n", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'D':
                        r = set_sanitized_path(&arg_directory, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Invalid root directory: %m");

                        break;

                case ARG_TEMPLATE:
                        r = set_sanitized_path(&arg_template, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Invalid template directory: %m");

                        break;

                case 'i':
                        r = set_sanitized_path(&arg_image, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Invalid image path: %m");

                        break;

                case 'x':
                        arg_ephemeral = true;
                        break;

                case 'u':
                        free(arg_user);
                        arg_user = strdup(optarg);
                        if (!arg_user)
                                return log_oom();

                        break;

                case ARG_NETWORK_BRIDGE:
                        arg_network_bridge = optarg;

                        /* fall through */

                case 'n':
                        arg_network_veth = true;
                        arg_private_network = true;
                        break;

                case ARG_NETWORK_INTERFACE:
                        if (strv_extend(&arg_network_interfaces, optarg) < 0)
                                return log_oom();

                        arg_private_network = true;
                        break;

                case ARG_NETWORK_MACVLAN:
                        if (strv_extend(&arg_network_macvlan, optarg) < 0)
                                return log_oom();

                        arg_private_network = true;
                        break;

                case ARG_NETWORK_IPVLAN:
                        if (strv_extend(&arg_network_ipvlan, optarg) < 0)
                                return log_oom();

                        /* fall through */

                case ARG_PRIVATE_NETWORK:
                        arg_private_network = true;
                        break;

                case 'b':
                        arg_boot = true;
                        break;

                case ARG_UUID:
                        r = sd_id128_from_string(optarg, &arg_uuid);
                        if (r < 0) {
                                log_error("Invalid UUID: %s", optarg);
                                return r;
                        }
                        break;

                case 'S':
                        arg_slice = optarg;
                        break;

                case 'M':
                        if (isempty(optarg)) {
                                free(arg_machine);
                                arg_machine = NULL;
                        } else {
                                if (!machine_name_is_valid(optarg)) {
                                        log_error("Invalid machine name: %s", optarg);
                                        return -EINVAL;
                                }

                                r = free_and_strdup(&arg_machine, optarg);
                                if (r < 0)
                                        return log_oom();

                                break;
                        }

                case 'Z':
                        arg_selinux_context = optarg;
                        break;

                case 'L':
                        arg_selinux_apifs_context = optarg;
                        break;

                case ARG_READ_ONLY:
                        arg_read_only = true;
                        break;

                case ARG_CAPABILITY:
                case ARG_DROP_CAPABILITY: {
                        const char *state, *word;
                        size_t length;

                        FOREACH_WORD_SEPARATOR(word, length, optarg, ",", state) {
                                _cleanup_free_ char *t;

                                t = strndup(word, length);
                                if (!t)
                                        return log_oom();

                                if (streq(t, "all")) {
                                        if (c == ARG_CAPABILITY)
                                                plus = (uint64_t) -1;
                                        else
                                                minus = (uint64_t) -1;
                                } else {
                                        int cap;

                                        cap = capability_from_name(t);
                                        if (cap < 0) {
                                                log_error("Failed to parse capability %s.", t);
                                                return -EINVAL;
                                        }

                                        if (c == ARG_CAPABILITY)
                                                plus |= 1ULL << (uint64_t) cap;
                                        else
                                                minus |= 1ULL << (uint64_t) cap;
                                }
                        }

                        break;
                }

                case 'j':
                        arg_link_journal = LINK_GUEST;
                        arg_link_journal_try = true;
                        break;

                case ARG_LINK_JOURNAL:
                        if (streq(optarg, "auto")) {
                                arg_link_journal = LINK_AUTO;
                                arg_link_journal_try = false;
                        } else if (streq(optarg, "no")) {
                                arg_link_journal = LINK_NO;
                                arg_link_journal_try = false;
                        } else if (streq(optarg, "guest")) {
                                arg_link_journal = LINK_GUEST;
                                arg_link_journal_try = false;
                        } else if (streq(optarg, "host")) {
                                arg_link_journal = LINK_HOST;
                                arg_link_journal_try = false;
                        } else if (streq(optarg, "try-guest")) {
                                arg_link_journal = LINK_GUEST;
                                arg_link_journal_try = true;
                        } else if (streq(optarg, "try-host")) {
                                arg_link_journal = LINK_HOST;
                                arg_link_journal_try = true;
                        } else {
                                log_error("Failed to parse link journal mode %s", optarg);
                                return -EINVAL;
                        }

                        break;

                case ARG_BIND:
                case ARG_BIND_RO: {
                        _cleanup_free_ char *a = NULL, *b = NULL;
                        char *e;
                        char ***x;

                        x = c == ARG_BIND ? &arg_bind : &arg_bind_ro;

                        e = strchr(optarg, ':');
                        if (e) {
                                a = strndup(optarg, e - optarg);
                                b = strdup(e + 1);
                        } else {
                                a = strdup(optarg);
                                b = strdup(optarg);
                        }

                        if (!a || !b)
                                return log_oom();

                        if (!path_is_absolute(a) || !path_is_absolute(b)) {
                                log_error("Invalid bind mount specification: %s", optarg);
                                return -EINVAL;
                        }

                        r = strv_extend(x, a);
                        if (r < 0)
                                return log_oom();

                        r = strv_extend(x, b);
                        if (r < 0)
                                return log_oom();

                        break;
                }

                case ARG_TMPFS: {
                        _cleanup_free_ char *a = NULL, *b = NULL;
                        char *e;

                        e = strchr(optarg, ':');
                        if (e) {
                                a = strndup(optarg, e - optarg);
                                b = strdup(e + 1);
                        } else {
                                a = strdup(optarg);
                                b = strdup("mode=0755");
                        }

                        if (!a || !b)
                                return log_oom();

                        if (!path_is_absolute(a)) {
                                log_error("Invalid tmpfs specification: %s", optarg);
                                return -EINVAL;
                        }

                        r = strv_push(&arg_tmpfs, a);
                        if (r < 0)
                                return log_oom();

                        a = NULL;

                        r = strv_push(&arg_tmpfs, b);
                        if (r < 0)
                                return log_oom();

                        b = NULL;

                        break;
                }

                case ARG_SETENV: {
                        char **n;

                        if (!env_assignment_is_valid(optarg)) {
                                log_error("Environment variable assignment '%s' is not valid.", optarg);
                                return -EINVAL;
                        }

                        n = strv_env_set(arg_setenv, optarg);
                        if (!n)
                                return log_oom();

                        strv_free(arg_setenv);
                        arg_setenv = n;
                        break;
                }

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_SHARE_SYSTEM:
                        arg_share_system = true;
                        break;

                case ARG_REGISTER:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --register= argument: %s", optarg);
                                return r;
                        }

                        arg_register = r;
                        break;

                case ARG_KEEP_UNIT:
                        arg_keep_unit = true;
                        break;

                case ARG_PERSONALITY:

                        arg_personality = personality_from_string(optarg);
                        if (arg_personality == 0xffffffffLU) {
                                log_error("Unknown or unsupported personality '%s'.", optarg);
                                return -EINVAL;
                        }

                        break;

                case ARG_VOLATILE:

                        if (!optarg)
                                arg_volatile = VOLATILE_YES;
                        else {
                                r = parse_boolean(optarg);
                                if (r < 0) {
                                        if (streq(optarg, "state"))
                                                arg_volatile = VOLATILE_STATE;
                                        else {
                                                log_error("Failed to parse --volatile= argument: %s", optarg);
                                                return r;
                                        }
                                } else
                                        arg_volatile = r ? VOLATILE_YES : VOLATILE_NO;
                        }

                        break;

                case 'p': {
                        const char *split, *e;
                        uint16_t container_port, host_port;
                        int protocol;
                        ExposePort *p;

                        if ((e = startswith(optarg, "tcp:")))
                                protocol = IPPROTO_TCP;
                        else if ((e = startswith(optarg, "udp:")))
                                protocol = IPPROTO_UDP;
                        else {
                                e = optarg;
                                protocol = IPPROTO_TCP;
                        }

                        split = strchr(e, ':');
                        if (split) {
                                char v[split - e + 1];

                                memcpy(v, e, split - e);
                                v[split - e] = 0;

                                r = safe_atou16(v, &host_port);
                                if (r < 0 || host_port <= 0) {
                                        log_error("Failed to parse host port: %s", optarg);
                                        return -EINVAL;
                                }

                                r = safe_atou16(split + 1, &container_port);
                        } else {
                                r = safe_atou16(e, &container_port);
                                host_port = container_port;
                        }

                        if (r < 0 || container_port <= 0) {
                                log_error("Failed to parse host port: %s", optarg);
                                return -EINVAL;
                        }

                        LIST_FOREACH(ports, p, arg_expose_ports) {
                                if (p->protocol == protocol && p->host_port == host_port) {
                                        log_error("Duplicate port specification: %s", optarg);
                                        return -EINVAL;
                                }
                        }

                        p = new(ExposePort, 1);
                        if (!p)
                                return log_oom();

                        p->protocol = protocol;
                        p->host_port = host_port;
                        p->container_port = container_port;

                        LIST_PREPEND(ports, arg_expose_ports, p);

                        break;
                }

                case ARG_PROPERTY:
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_PRIVATE_USERS:
                        if (optarg) {
                                _cleanup_free_ char *buffer = NULL;
                                const char *range, *shift;

                                range = strchr(optarg, ':');
                                if (range) {
                                        buffer = strndup(optarg, range - optarg);
                                        if (!buffer)
                                                return log_oom();
                                        shift = buffer;

                                        range++;
                                        if (safe_atou32(range, &arg_uid_range) < 0 || arg_uid_range <= 0) {
                                                log_error("Failed to parse UID range: %s", range);
                                                return -EINVAL;
                                        }
                                } else
                                        shift = optarg;

                                if (parse_uid(shift, &arg_uid_shift) < 0) {
                                        log_error("Failed to parse UID: %s", optarg);
                                        return -EINVAL;
                                }
                        }

                        arg_userns = true;
                        break;

                case ARG_KILL_SIGNAL:
                        arg_kill_signal = signal_from_string_try_harder(optarg);
                        if (arg_kill_signal < 0) {
                                log_error("Cannot parse signal: %s", optarg);
                                return -EINVAL;
                        }

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_share_system)
                arg_register = false;

        if (arg_boot && arg_share_system) {
                log_error("--boot and --share-system may not be combined.");
                return -EINVAL;
        }

        if (arg_keep_unit && cg_pid_get_owner_uid(0, NULL) >= 0) {
                log_error("--keep-unit may not be used when invoked from a user session.");
                return -EINVAL;
        }

        if (arg_directory && arg_image) {
                log_error("--directory= and --image= may not be combined.");
                return -EINVAL;
        }

        if (arg_template && arg_image) {
                log_error("--template= and --image= may not be combined.");
                return -EINVAL;
        }

        if (arg_template && !(arg_directory || arg_machine)) {
                log_error("--template= needs --directory= or --machine=.");
                return -EINVAL;
        }

        if (arg_ephemeral && arg_template) {
                log_error("--ephemeral and --template= may not be combined.");
                return -EINVAL;
        }

        if (arg_ephemeral && arg_image) {
                log_error("--ephemeral and --image= may not be combined.");
                return -EINVAL;
        }

        if (arg_ephemeral && !IN_SET(arg_link_journal, LINK_NO, LINK_AUTO)) {
                log_error("--ephemeral and --link-journal= may not be combined.");
                return -EINVAL;
        }

        if (arg_volatile != VOLATILE_NO && arg_read_only) {
                log_error("Cannot combine --read-only with --volatile. Note that --volatile already implies a read-only base hierarchy.");
                return -EINVAL;
        }

        if (arg_expose_ports && !arg_private_network) {
                log_error("Cannot use --port= without private networking.");
                return -EINVAL;
        }

        arg_retain = (arg_retain | plus | (arg_private_network ? 1ULL << CAP_NET_ADMIN : 0)) & ~minus;

        if (arg_boot && arg_kill_signal <= 0)
                arg_kill_signal = SIGRTMIN+3;

        return 1;
}

static int mount_all(const char *dest) {

        typedef struct MountPoint {
                const char *what;
                const char *where;
                const char *type;
                const char *options;
                unsigned long flags;
                bool fatal;
        } MountPoint;

        static const MountPoint mount_table[] = {
                { "proc",      "/proc",     "proc",  NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV,           true  },
                { "/proc/sys", "/proc/sys", NULL,    NULL,        MS_BIND,                                true  },   /* Bind mount first */
                { NULL,        "/proc/sys", NULL,    NULL,        MS_BIND|MS_RDONLY|MS_REMOUNT,           true  },   /* Then, make it r/o */
                { "sysfs",     "/sys",      "sysfs", NULL,        MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, true  },
                { "tmpfs",     "/dev",      "tmpfs", "mode=755",  MS_NOSUID|MS_STRICTATIME,               true  },
                { "devpts",    "/dev/pts",  "devpts","newinstance,ptmxmode=0666,mode=620,gid=" STRINGIFY(TTY_GID), MS_NOSUID|MS_NOEXEC, true },
                { "tmpfs",     "/dev/shm",  "tmpfs", "mode=1777", MS_NOSUID|MS_NODEV|MS_STRICTATIME,      true  },
                { "tmpfs",     "/run",      "tmpfs", "mode=755",  MS_NOSUID|MS_NODEV|MS_STRICTATIME,      true  },
                { "tmpfs",     "/tmp",      "tmpfs", "mode=1777", MS_STRICTATIME,                         true  },
#ifdef HAVE_SELINUX
                { "/sys/fs/selinux", "/sys/fs/selinux", NULL, NULL, MS_BIND,                              false },  /* Bind mount first */
                { NULL,              "/sys/fs/selinux", NULL, NULL, MS_BIND|MS_RDONLY|MS_REMOUNT,         false },  /* Then, make it r/o */
#endif
        };

        unsigned k;
        int r = 0;

        for (k = 0; k < ELEMENTSOF(mount_table); k++) {
                _cleanup_free_ char *where = NULL, *options = NULL;
                const char *o;
                int t;

                where = strjoin(dest, "/", mount_table[k].where, NULL);
                if (!where)
                        return log_oom();

                t = path_is_mount_point(where, true);
                if (t < 0 && t != -ENOENT) {
                        log_error_errno(t, "Failed to detect whether %s is a mount point: %m", where);

                        if (r == 0)
                                r = t;

                        continue;
                }

                /* Skip this entry if it is not a remount. */
                if (mount_table[k].what && t > 0)
                        continue;

                t = mkdir_p(where, 0755);
                if (t < 0) {
                        if (mount_table[k].fatal) {
                               log_error_errno(t, "Failed to create directory %s: %m", where);

                                if (r == 0)
                                        r = t;
                        } else
                               log_warning_errno(t, "Failed to create directory %s: %m", where);

                        continue;
                }

#ifdef HAVE_SELINUX
                if (arg_selinux_apifs_context &&
                    (streq_ptr(mount_table[k].what, "tmpfs") || streq_ptr(mount_table[k].what, "devpts"))) {
                        options = strjoin(mount_table[k].options, ",context=\"", arg_selinux_apifs_context, "\"", NULL);
                        if (!options)
                                return log_oom();

                        o = options;
                } else
#endif
                        o = mount_table[k].options;

                if (arg_userns && arg_uid_shift != UID_INVALID && streq_ptr(mount_table[k].type, "tmpfs")) {
                        char *uid_options = NULL;

                        if (o)
                                asprintf(&uid_options, "%s,uid=" UID_FMT ",gid=" UID_FMT, o, arg_uid_shift, arg_uid_shift);
                        else
                                asprintf(&uid_options, "uid=" UID_FMT ",gid=" UID_FMT, arg_uid_shift, arg_uid_shift);
                        if (!uid_options)
                                return log_oom();

                        free(options);
                        o = options = uid_options;
                }

                if (mount(mount_table[k].what,
                          where,
                          mount_table[k].type,
                          mount_table[k].flags,
                          o) < 0) {

                        if (mount_table[k].fatal) {
                                log_error_errno(errno, "mount(%s) failed: %m", where);

                                if (r == 0)
                                        r = -errno;
                        } else
                                log_warning_errno(errno, "mount(%s) failed: %m", where);
                }
        }

        return r;
}

static int mount_binds(const char *dest, char **l, bool ro) {
        char **x, **y;

        STRV_FOREACH_PAIR(x, y, l) {
                _cleanup_free_ char *where = NULL;
                struct stat source_st, dest_st;
                int r;

                if (stat(*x, &source_st) < 0)
                        return log_error_errno(errno, "Failed to stat %s: %m", *x);

                where = strappend(dest, *y);
                if (!where)
                        return log_oom();

                r = stat(where, &dest_st);
                if (r == 0) {
                        if (S_ISDIR(source_st.st_mode) && !S_ISDIR(dest_st.st_mode)) {
                                log_error("Cannot bind mount directory %s on file %s.", *x, where);
                                return -EINVAL;
                        }
                        if (!S_ISDIR(source_st.st_mode) && S_ISDIR(dest_st.st_mode)) {
                                log_error("Cannot bind mount file %s on directory %s.", *x, where);
                                return -EINVAL;
                        }
                } else if (errno == ENOENT) {
                        r = mkdir_parents_label(where, 0755);
                        if (r < 0)
                                return log_error_errno(r, "Failed to bind mount %s: %m", *x);
                } else {
                        log_error_errno(errno, "Failed to bind mount %s: %m", *x);
                        return -errno;
                }

                /* Create the mount point. Any non-directory file can be
                 * mounted on any non-directory file (regular, fifo, socket,
                 * char, block).
                 */
                if (S_ISDIR(source_st.st_mode)) {
                        r = mkdir_label(where, 0755);
                        if (r < 0 && errno != EEXIST)
                                return log_error_errno(r, "Failed to create mount point %s: %m", where);
                } else {
                        r = touch(where);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create mount point %s: %m", where);
                }

                if (mount(*x, where, NULL, MS_BIND, NULL) < 0)
                        return log_error_errno(errno, "mount(%s) failed: %m", where);

                if (ro) {
                        r = bind_remount_recursive(where, true);
                        if (r < 0)
                                return log_error_errno(r, "Read-Only bind mount failed: %m");
                }
        }

        return 0;
}

static int mount_cgroup_hierarchy(const char *dest, const char *controller, const char *hierarchy, bool read_only) {
        char *to;
        int r;

        to = strjoina(dest, "/sys/fs/cgroup/", hierarchy);

        r = path_is_mount_point(to, false);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to determine if %s is mounted already: %m", to);
        if (r > 0)
                return 0;

        mkdir_p(to, 0755);

        /* The superblock mount options of the mount point need to be
         * identical to the hosts', and hence writable... */
        if (mount("cgroup", to, "cgroup", MS_NOSUID|MS_NOEXEC|MS_NODEV, controller) < 0)
                return log_error_errno(errno, "Failed to mount to %s: %m", to);

        /* ... hence let's only make the bind mount read-only, not the
         * superblock. */
        if (read_only) {
                if (mount(NULL, to, NULL, MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL) < 0)
                        return log_error_errno(errno, "Failed to remount %s read-only: %m", to);
        }
        return 1;
}

static int mount_cgroup(const char *dest) {
        _cleanup_set_free_free_ Set *controllers = NULL;
        _cleanup_free_ char *own_cgroup_path = NULL;
        const char *cgroup_root, *systemd_root, *systemd_own;
        int r;

        controllers = set_new(&string_hash_ops);
        if (!controllers)
                return log_oom();

        r = cg_kernel_controllers(controllers);
        if (r < 0)
                return log_error_errno(r, "Failed to determine cgroup controllers: %m");

        r = cg_pid_get_path(NULL, 0, &own_cgroup_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine our own cgroup path: %m");

        cgroup_root = strjoina(dest, "/sys/fs/cgroup");
        if (mount("tmpfs", cgroup_root, "tmpfs", MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME, "mode=755") < 0)
                return log_error_errno(errno, "Failed to mount tmpfs to /sys/fs/cgroup: %m");

        for (;;) {
                _cleanup_free_ char *controller = NULL, *origin = NULL, *combined = NULL;

                controller = set_steal_first(controllers);
                if (!controller)
                        break;

                origin = strappend("/sys/fs/cgroup/", controller);
                if (!origin)
                        return log_oom();

                r = readlink_malloc(origin, &combined);
                if (r == -EINVAL) {
                        /* Not a symbolic link, but directly a single cgroup hierarchy */

                        r = mount_cgroup_hierarchy(dest, controller, controller, true);
                        if (r < 0)
                                return r;

                } else if (r < 0)
                        return log_error_errno(r, "Failed to read link %s: %m", origin);
                else {
                        _cleanup_free_ char *target = NULL;

                        target = strjoin(dest, "/sys/fs/cgroup/", controller, NULL);
                        if (!target)
                                return log_oom();

                        /* A symbolic link, a combination of controllers in one hierarchy */

                        if (!filename_is_valid(combined)) {
                                log_warning("Ignoring invalid combined hierarchy %s.", combined);
                                continue;
                        }

                        r = mount_cgroup_hierarchy(dest, combined, combined, true);
                        if (r < 0)
                                return r;

                        if (symlink(combined, target) < 0)
                                return log_error_errno(errno, "Failed to create symlink for combined hierarchy: %m");
                }
        }

        r = mount_cgroup_hierarchy(dest, "name=systemd,xattr", "systemd", false);
        if (r < 0)
                return r;

        /* Make our own cgroup a (writable) bind mount */
        systemd_own = strjoina(dest, "/sys/fs/cgroup/systemd", own_cgroup_path);
        if (mount(systemd_own, systemd_own,  NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Failed to turn %s into a bind mount: %m", own_cgroup_path);

        /* And then remount the systemd cgroup root read-only */
        systemd_root = strjoina(dest, "/sys/fs/cgroup/systemd");
        if (mount(NULL, systemd_root, NULL, MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, NULL) < 0)
                return log_error_errno(errno, "Failed to mount cgroup root read-only: %m");

        if (mount(NULL, cgroup_root, NULL, MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY, "mode=755") < 0)
                return log_error_errno(errno, "Failed to remount %s read-only: %m", cgroup_root);

        return 0;
}

static int mount_tmpfs(const char *dest) {
        char **i, **o;

        STRV_FOREACH_PAIR(i, o, arg_tmpfs) {
                _cleanup_free_ char *where = NULL;
                int r;

                where = strappend(dest, *i);
                if (!where)
                        return log_oom();

                r = mkdir_label(where, 0755);
                if (r < 0 && r != -EEXIST)
                        return log_error_errno(r, "Creating mount point for tmpfs %s failed: %m", where);

                if (mount("tmpfs", where, "tmpfs", MS_NODEV|MS_STRICTATIME, *o) < 0)
                        return log_error_errno(errno, "tmpfs mount to %s failed: %m", where);
        }

        return 0;
}

static int setup_timezone(const char *dest) {
        _cleanup_free_ char *where = NULL, *p = NULL, *q = NULL, *check = NULL, *what = NULL;
        char *z, *y;
        int r;

        assert(dest);

        /* Fix the timezone, if possible */
        r = readlink_malloc("/etc/localtime", &p);
        if (r < 0) {
                log_warning("/etc/localtime is not a symlink, not updating container timezone.");
                return 0;
        }

        z = path_startswith(p, "../usr/share/zoneinfo/");
        if (!z)
                z = path_startswith(p, "/usr/share/zoneinfo/");
        if (!z) {
                log_warning("/etc/localtime does not point into /usr/share/zoneinfo/, not updating container timezone.");
                return 0;
        }

        where = strappend(dest, "/etc/localtime");
        if (!where)
                return log_oom();

        r = readlink_malloc(where, &q);
        if (r >= 0) {
                y = path_startswith(q, "../usr/share/zoneinfo/");
                if (!y)
                        y = path_startswith(q, "/usr/share/zoneinfo/");

                /* Already pointing to the right place? Then do nothing .. */
                if (y && streq(y, z))
                        return 0;
        }

        check = strjoin(dest, "/usr/share/zoneinfo/", z, NULL);
        if (!check)
                return log_oom();

        if (access(check, F_OK) < 0) {
                log_warning("Timezone %s does not exist in container, not updating container timezone.", z);
                return 0;
        }

        what = strappend("../usr/share/zoneinfo/", z);
        if (!what)
                return log_oom();

        r = mkdir_parents(where, 0755);
        if (r < 0) {
                log_error_errno(r, "Failed to create directory for timezone info %s in container: %m", where);

                return 0;
        }

        r = unlink(where);
        if (r < 0 && errno != ENOENT) {
                log_error_errno(errno, "Failed to remove existing timezone info %s in container: %m", where);

                return 0;
        }

        if (symlink(what, where) < 0) {
                log_error_errno(errno, "Failed to correct timezone of container: %m");
                return 0;
        }

        return 0;
}

static int setup_resolv_conf(const char *dest) {
        _cleanup_free_ char *where = NULL;
        int r;

        assert(dest);

        if (arg_private_network)
                return 0;

        /* Fix resolv.conf, if possible */
        where = strappend(dest, "/etc/resolv.conf");
        if (!where)
                return log_oom();

        /* We don't really care for the results of this really. If it
         * fails, it fails, but meh... */
        r = mkdir_parents(where, 0755);
        if (r < 0) {
                log_warning_errno(r, "Failed to create parent directory for resolv.conf %s: %m", where);

                return 0;
        }

        r = copy_file("/etc/resolv.conf", where, O_TRUNC|O_NOFOLLOW, 0644, 0);
        if (r < 0) {
                log_warning_errno(r, "Failed to copy /etc/resolv.conf to %s: %m", where);

                return 0;
        }

        return 0;
}

static int setup_volatile_state(const char *directory) {
        const char *p;
        int r;

        assert(directory);

        if (arg_volatile != VOLATILE_STATE)
                return 0;

        /* --volatile=state means we simply overmount /var
           with a tmpfs, and the rest read-only. */

        r = bind_remount_recursive(directory, true);
        if (r < 0)
                return log_error_errno(r, "Failed to remount %s read-only: %m", directory);

        p = strjoina(directory, "/var");
        r = mkdir(p, 0755);
        if (r < 0 && errno != EEXIST)
                return log_error_errno(errno, "Failed to create %s: %m", directory);

        if (mount("tmpfs", p, "tmpfs", MS_STRICTATIME, "mode=755") < 0)
                return log_error_errno(errno, "Failed to mount tmpfs to /var: %m");

        return 0;
}

static int setup_volatile(const char *directory) {
        bool tmpfs_mounted = false, bind_mounted = false;
        char template[] = "/tmp/nspawn-volatile-XXXXXX";
        const char *f, *t;
        int r;

        assert(directory);

        if (arg_volatile != VOLATILE_YES)
                return 0;

        /* --volatile=yes means we mount a tmpfs to the root dir, and
           the original /usr to use inside it, and that read-only. */

        if (!mkdtemp(template))
                return log_error_errno(errno, "Failed to create temporary directory: %m");

        if (mount("tmpfs", template, "tmpfs", MS_STRICTATIME, "mode=755") < 0) {
                log_error_errno(errno, "Failed to mount tmpfs for root directory: %m");
                r = -errno;
                goto fail;
        }

        tmpfs_mounted = true;

        f = strjoina(directory, "/usr");
        t = strjoina(template, "/usr");

        r = mkdir(t, 0755);
        if (r < 0 && errno != EEXIST) {
                log_error_errno(errno, "Failed to create %s: %m", t);
                r = -errno;
                goto fail;
        }

        if (mount(f, t, NULL, MS_BIND|MS_REC, NULL) < 0) {
                log_error_errno(errno, "Failed to create /usr bind mount: %m");
                r = -errno;
                goto fail;
        }

        bind_mounted = true;

        r = bind_remount_recursive(t, true);
        if (r < 0) {
                log_error_errno(r, "Failed to remount %s read-only: %m", t);
                goto fail;
        }

        if (mount(template, directory, NULL, MS_MOVE, NULL) < 0) {
                log_error_errno(errno, "Failed to move root mount: %m");
                r = -errno;
                goto fail;
        }

        rmdir(template);

        return 0;

fail:
        if (bind_mounted)
                umount(t);
        if (tmpfs_mounted)
                umount(template);
        rmdir(template);
        return r;
}

static char* id128_format_as_uuid(sd_id128_t id, char s[37]) {

        snprintf(s, 37,
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 SD_ID128_FORMAT_VAL(id));

        return s;
}

static int setup_boot_id(const char *dest) {
        _cleanup_free_ char *from = NULL, *to = NULL;
        sd_id128_t rnd = {};
        char as_uuid[37];
        int r;

        assert(dest);

        if (arg_share_system)
                return 0;

        /* Generate a new randomized boot ID, so that each boot-up of
         * the container gets a new one */

        from = strappend(dest, "/dev/proc-sys-kernel-random-boot-id");
        to = strappend(dest, "/proc/sys/kernel/random/boot_id");
        if (!from || !to)
                return log_oom();

        r = sd_id128_randomize(&rnd);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random boot id: %m");

        id128_format_as_uuid(rnd, as_uuid);

        r = write_string_file(from, as_uuid);
        if (r < 0)
                return log_error_errno(r, "Failed to write boot id: %m");

        if (mount(from, to, NULL, MS_BIND, NULL) < 0) {
                log_error_errno(errno, "Failed to bind mount boot id: %m");
                r = -errno;
        } else if (mount(from, to, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL))
                log_warning_errno(errno, "Failed to make boot id read-only: %m");

        unlink(from);
        return r;
}

static int copy_devnodes(const char *dest) {

        static const char devnodes[] =
                "null\0"
                "zero\0"
                "full\0"
                "random\0"
                "urandom\0"
                "tty\0"
                "net/tun\0";

        const char *d;
        int r = 0;
        _cleanup_umask_ mode_t u;

        assert(dest);

        u = umask(0000);

        NULSTR_FOREACH(d, devnodes) {
                _cleanup_free_ char *from = NULL, *to = NULL;
                struct stat st;

                from = strappend("/dev/", d);
                to = strjoin(dest, "/dev/", d, NULL);
                if (!from || !to)
                        return log_oom();

                if (stat(from, &st) < 0) {

                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to stat %s: %m", from);

                } else if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {

                        log_error("%s is not a char or block device, cannot copy", from);
                        return -EIO;

                } else {
                        r = mkdir_parents(to, 0775);
                        if (r < 0) {
                                log_error_errno(r, "Failed to create parent directory of %s: %m", to);
                                return -r;
                        }

                        if (mknod(to, st.st_mode, st.st_rdev) < 0) {
                                if (errno != EPERM)
                                        return log_error_errno(errno, "mknod(%s) failed: %m", to);

                                /* Some systems abusively restrict mknod but
                                 * allow bind mounts. */
                                r = touch(to);
                                if (r < 0)
                                        return log_error_errno(r, "touch (%s) failed: %m", to);
                                if (mount(from, to, NULL, MS_BIND, NULL) < 0)
                                        return log_error_errno(errno, "Both mknod and bind mount (%s) failed: %m", to);
                        }

                        if (arg_userns && arg_uid_shift != UID_INVALID)
                                if (lchown(to, arg_uid_shift, arg_uid_shift) < 0)
                                        return log_error_errno(errno, "chown() of device node %s failed: %m", to);
                }
        }

        return r;
}

static int setup_ptmx(const char *dest) {
        _cleanup_free_ char *p = NULL;

        p = strappend(dest, "/dev/ptmx");
        if (!p)
                return log_oom();

        if (symlink("pts/ptmx", p) < 0)
                return log_error_errno(errno, "Failed to create /dev/ptmx symlink: %m");

        if (arg_userns && arg_uid_shift != UID_INVALID)
                if (lchown(p, arg_uid_shift, arg_uid_shift) < 0)
                        return log_error_errno(errno, "lchown() of symlink %s failed: %m", p);

        return 0;
}

static int setup_dev_console(const char *dest, const char *console) {
        _cleanup_umask_ mode_t u;
        const char *to;
        int r;

        assert(dest);
        assert(console);

        u = umask(0000);

        r = chmod_and_chown(console, 0600, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to correct access mode for TTY: %m");

        /* We need to bind mount the right tty to /dev/console since
         * ptys can only exist on pts file systems. To have something
         * to bind mount things on we create a empty regular file. */

        to = strjoina(dest, "/dev/console");
        r = touch(to);
        if (r < 0)
                return log_error_errno(r, "touch() for /dev/console failed: %m");

        if (mount(console, to, NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Bind mount for /dev/console failed: %m");

        return 0;
}

static int setup_kmsg(const char *dest, int kmsg_socket) {
        _cleanup_free_ char *from = NULL, *to = NULL;
        _cleanup_umask_ mode_t u;
        int r, fd, k;
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;

        assert(dest);
        assert(kmsg_socket >= 0);

        u = umask(0000);

        /* We create the kmsg FIFO as /dev/kmsg, but immediately
         * delete it after bind mounting it to /proc/kmsg. While FIFOs
         * on the reading side behave very similar to /proc/kmsg,
         * their writing side behaves differently from /dev/kmsg in
         * that writing blocks when nothing is reading. In order to
         * avoid any problems with containers deadlocking due to this
         * we simply make /dev/kmsg unavailable to the container. */
        if (asprintf(&from, "%s/dev/kmsg", dest) < 0 ||
            asprintf(&to, "%s/proc/kmsg", dest) < 0)
                return log_oom();

        if (mkfifo(from, 0600) < 0)
                return log_error_errno(errno, "mkfifo() for /dev/kmsg failed: %m");

        r = chmod_and_chown(from, 0600, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to correct access mode for /dev/kmsg: %m");

        if (mount(from, to, NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Bind mount for /proc/kmsg failed: %m");

        fd = open(from, O_RDWR|O_NDELAY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open fifo: %m");

        cmsg = CMSG_FIRSTHDR(&mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

        mh.msg_controllen = cmsg->cmsg_len;

        /* Store away the fd in the socket, so that it stays open as
         * long as we run the child */
        k = sendmsg(kmsg_socket, &mh, MSG_NOSIGNAL);
        safe_close(fd);

        if (k < 0)
                return log_error_errno(errno, "Failed to send FIFO fd: %m");

        /* And now make the FIFO unavailable as /dev/kmsg... */
        unlink(from);
        return 0;
}

static int send_rtnl(int send_fd) {
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        _cleanup_close_ int fd = -1;
        ssize_t k;

        assert(send_fd >= 0);

        if (!arg_expose_ports)
                return 0;

        fd = socket(PF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_ROUTE);
        if (fd < 0)
                return log_error_errno(errno, "failed to allocate container netlink: %m");

        cmsg = CMSG_FIRSTHDR(&mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

        mh.msg_controllen = cmsg->cmsg_len;

        /* Store away the fd in the socket, so that it stays open as
         * long as we run the child */
        k = sendmsg(send_fd, &mh, MSG_NOSIGNAL);
        if (k < 0)
                return log_error_errno(errno, "Failed to send netlink fd: %m");

        return 0;
}

static int flush_ports(union in_addr_union *exposed) {
        ExposePort *p;
        int r, af = AF_INET;

        assert(exposed);

        if (!arg_expose_ports)
                return 0;

        if (in_addr_is_null(af, exposed))
                return 0;

        log_debug("Lost IP address.");

        LIST_FOREACH(ports, p, arg_expose_ports) {
                r = fw_add_local_dnat(false,
                                      af,
                                      p->protocol,
                                      NULL,
                                      NULL, 0,
                                      NULL, 0,
                                      p->host_port,
                                      exposed,
                                      p->container_port,
                                      NULL);
                if (r < 0)
                        log_warning_errno(r, "Failed to modify firewall: %m");
        }

        *exposed = IN_ADDR_NULL;
        return 0;
}

static int expose_ports(sd_rtnl *rtnl, union in_addr_union *exposed) {
        _cleanup_free_ struct local_address *addresses = NULL;
        _cleanup_free_ char *pretty = NULL;
        union in_addr_union new_exposed;
        ExposePort *p;
        bool add;
        int af = AF_INET, r;

        assert(exposed);

        /* Invoked each time an address is added or removed inside the
         * container */

        if (!arg_expose_ports)
                return 0;

        r = local_addresses(rtnl, 0, af, &addresses);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate local addresses: %m");

        add = r > 0 &&
                addresses[0].family == af &&
                addresses[0].scope < RT_SCOPE_LINK;

        if (!add)
                return flush_ports(exposed);

        new_exposed = addresses[0].address;
        if (in_addr_equal(af, exposed, &new_exposed))
                return 0;

        in_addr_to_string(af, &new_exposed, &pretty);
        log_debug("New container IP is %s.", strna(pretty));

        LIST_FOREACH(ports, p, arg_expose_ports) {

                r = fw_add_local_dnat(true,
                                      af,
                                      p->protocol,
                                      NULL,
                                      NULL, 0,
                                      NULL, 0,
                                      p->host_port,
                                      &new_exposed,
                                      p->container_port,
                                      in_addr_is_null(af, exposed) ? NULL : exposed);
                if (r < 0)
                        log_warning_errno(r, "Failed to modify firewall: %m");
        }

        *exposed = new_exposed;
        return 0;
}

static int on_address_change(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        union in_addr_union *exposed = userdata;

        assert(rtnl);
        assert(m);
        assert(exposed);

        expose_ports(rtnl, exposed);
        return 0;
}

static int watch_rtnl(sd_event *event, int recv_fd, union in_addr_union *exposed, sd_rtnl **ret) {
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(int))];
        } control = {};
        struct msghdr mh = {
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        int fd, r;
        ssize_t k;

        assert(event);
        assert(recv_fd >= 0);
        assert(ret);

        if (!arg_expose_ports)
                return 0;

        k = recvmsg(recv_fd, &mh, MSG_NOSIGNAL);
        if (k < 0)
                return log_error_errno(errno, "Failed to recv netlink fd: %m");

        cmsg = CMSG_FIRSTHDR(&mh);
        assert(cmsg->cmsg_level == SOL_SOCKET);
        assert(cmsg->cmsg_type == SCM_RIGHTS);
        assert(cmsg->cmsg_len == CMSG_LEN(sizeof(int)));
        memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));

        r = sd_rtnl_open_fd(&rtnl, fd, 1, RTNLGRP_IPV4_IFADDR);
        if (r < 0) {
                safe_close(fd);
                return log_error_errno(r, "Failed to create rtnl object: %m");
        }

        r = sd_rtnl_add_match(rtnl, RTM_NEWADDR, on_address_change, exposed);
        if (r < 0)
                return log_error_errno(r, "Failed to subscribe to RTM_NEWADDR messages: %m");

        r = sd_rtnl_add_match(rtnl, RTM_DELADDR, on_address_change, exposed);
        if (r < 0)
                return log_error_errno(r, "Failed to subscribe to RTM_DELADDR messages: %m");

        r = sd_rtnl_attach_event(rtnl, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to add to even loop: %m");

        *ret = rtnl;
        rtnl = NULL;

        return 0;
}

static int setup_hostname(void) {

        if (arg_share_system)
                return 0;

        if (sethostname_idempotent(arg_machine) < 0)
                return -errno;

        return 0;
}

static int setup_journal(const char *directory) {
        sd_id128_t machine_id, this_id;
        _cleanup_free_ char *p = NULL, *b = NULL, *q = NULL, *d = NULL;
        char *id;
        int r;

        /* Don't link journals in ephemeral mode */
        if (arg_ephemeral)
                return 0;

        p = strappend(directory, "/etc/machine-id");
        if (!p)
                return log_oom();

        r = read_one_line_file(p, &b);
        if (r == -ENOENT && arg_link_journal == LINK_AUTO)
                return 0;
        else if (r < 0)
                return log_error_errno(r, "Failed to read machine ID from %s: %m", p);

        id = strstrip(b);
        if (isempty(id) && arg_link_journal == LINK_AUTO)
                return 0;

        /* Verify validity */
        r = sd_id128_from_string(id, &machine_id);
        if (r < 0)
                return log_error_errno(r, "Failed to parse machine ID from %s: %m", p);

        r = sd_id128_get_machine(&this_id);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve machine ID: %m");

        if (sd_id128_equal(machine_id, this_id)) {
                log_full(arg_link_journal == LINK_AUTO ? LOG_WARNING : LOG_ERR,
                         "Host and machine ids are equal (%s): refusing to link journals", id);
                if (arg_link_journal == LINK_AUTO)
                        return 0;
                return -EEXIST;
        }

        if (arg_link_journal == LINK_NO)
                return 0;

        free(p);
        p = strappend("/var/log/journal/", id);
        q = strjoin(directory, "/var/log/journal/", id, NULL);
        if (!p || !q)
                return log_oom();

        if (path_is_mount_point(p, false) > 0) {
                if (arg_link_journal != LINK_AUTO) {
                        log_error("%s: already a mount point, refusing to use for journal", p);
                        return -EEXIST;
                }

                return 0;
        }

        if (path_is_mount_point(q, false) > 0) {
                if (arg_link_journal != LINK_AUTO) {
                        log_error("%s: already a mount point, refusing to use for journal", q);
                        return -EEXIST;
                }

                return 0;
        }

        r = readlink_and_make_absolute(p, &d);
        if (r >= 0) {
                if ((arg_link_journal == LINK_GUEST ||
                     arg_link_journal == LINK_AUTO) &&
                    path_equal(d, q)) {

                        r = mkdir_p(q, 0755);
                        if (r < 0)
                                log_warning_errno(errno, "Failed to create directory %s: %m", q);
                        return 0;
                }

                if (unlink(p) < 0)
                        return log_error_errno(errno, "Failed to remove symlink %s: %m", p);
        } else if (r == -EINVAL) {

                if (arg_link_journal == LINK_GUEST &&
                    rmdir(p) < 0) {

                        if (errno == ENOTDIR) {
                                log_error("%s already exists and is neither a symlink nor a directory", p);
                                return r;
                        } else {
                                log_error_errno(errno, "Failed to remove %s: %m", p);
                                return -errno;
                        }
                }
        } else if (r != -ENOENT) {
                log_error_errno(errno, "readlink(%s) failed: %m", p);
                return r;
        }

        if (arg_link_journal == LINK_GUEST) {

                if (symlink(q, p) < 0) {
                        if (arg_link_journal_try) {
                                log_debug_errno(errno, "Failed to symlink %s to %s, skipping journal setup: %m", q, p);
                                return 0;
                        } else {
                                log_error_errno(errno, "Failed to symlink %s to %s: %m", q, p);
                                return -errno;
                        }
                }

                r = mkdir_p(q, 0755);
                if (r < 0)
                        log_warning_errno(errno, "Failed to create directory %s: %m", q);
                return 0;
        }

        if (arg_link_journal == LINK_HOST) {
                /* don't create parents here -- if the host doesn't have
                 * permanent journal set up, don't force it here */
                r = mkdir(p, 0755);
                if (r < 0) {
                        if (arg_link_journal_try) {
                                log_debug_errno(errno, "Failed to create %s, skipping journal setup: %m", p);
                                return 0;
                        } else {
                                log_error_errno(errno, "Failed to create %s: %m", p);
                                return r;
                        }
                }

        } else if (access(p, F_OK) < 0)
                return 0;

        if (dir_is_empty(q) == 0)
                log_warning("%s is not empty, proceeding anyway.", q);

        r = mkdir_p(q, 0755);
        if (r < 0) {
                log_error_errno(errno, "Failed to create %s: %m", q);
                return r;
        }

        if (mount(p, q, NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Failed to bind mount journal from host into guest: %m");

        return 0;
}

static int drop_capabilities(void) {
        return capability_bounding_set_drop(~arg_retain, false);
}

static int register_machine(pid_t pid, int local_ifindex) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        int r;

        if (!arg_register)
                return 0;

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open system bus: %m");

        if (arg_keep_unit) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "RegisterMachineWithNetwork",
                                &error,
                                NULL,
                                "sayssusai",
                                arg_machine,
                                SD_BUS_MESSAGE_APPEND_ID128(arg_uuid),
                                "nspawn",
                                "container",
                                (uint32_t) pid,
                                strempty(arg_directory),
                                local_ifindex > 0 ? 1 : 0, local_ifindex);
        } else {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
                char **i;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "CreateMachineWithNetwork");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(
                                m,
                                "sayssusai",
                                arg_machine,
                                SD_BUS_MESSAGE_APPEND_ID128(arg_uuid),
                                "nspawn",
                                "container",
                                (uint32_t) pid,
                                strempty(arg_directory),
                                local_ifindex > 0 ? 1 : 0, local_ifindex);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_open_container(m, 'a', "(sv)");
                if (r < 0)
                        return bus_log_create_error(r);

                if (!isempty(arg_slice)) {
                        r = sd_bus_message_append(m, "(sv)", "Slice", "s", arg_slice);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_message_append(m, "(sv)", "DevicePolicy", "s", "strict");
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_message_append(m, "(sv)", "DeviceAllow", "a(ss)", 9,
                                          /* Allow the container to
                                           * access and create the API
                                           * device nodes, so that
                                           * PrivateDevices= in the
                                           * container can work
                                           * fine */
                                          "/dev/null", "rwm",
                                          "/dev/zero", "rwm",
                                          "/dev/full", "rwm",
                                          "/dev/random", "rwm",
                                          "/dev/urandom", "rwm",
                                          "/dev/tty", "rwm",
                                          "/dev/net/tun", "rwm",
                                          /* Allow the container
                                           * access to ptys. However,
                                           * do not permit the
                                           * container to ever create
                                           * these device nodes. */
                                          "/dev/pts/ptmx", "rw",
                                          "char-pts", "rw");
                if (r < 0)
                        return log_error_errno(r, "Failed to add device whitelist: %m");

                STRV_FOREACH(i, arg_property) {
                        r = sd_bus_message_open_container(m, 'r', "sv");
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = bus_append_unit_property_assignment(m, *i);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_close_container(m);
                        if (r < 0)
                                return bus_log_create_error(r);
                }

                r = sd_bus_message_close_container(m);
                if (r < 0)
                        return bus_log_create_error(r);

                r = sd_bus_call(bus, m, 0, &error, NULL);
        }

        if (r < 0) {
                log_error("Failed to register machine: %s", bus_error_message(&error, r));
                return r;
        }

        return 0;
}

static int terminate_machine(pid_t pid) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        const char *path;
        int r;

        if (!arg_register)
                return 0;

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open system bus: %m");

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "GetMachineByPID",
                        &error,
                        &reply,
                        "u",
                        (uint32_t) pid);
        if (r < 0) {
                /* Note that the machine might already have been
                 * cleaned up automatically, hence don't consider it a
                 * failure if we cannot get the machine object. */
                log_debug("Failed to get machine: %s", bus_error_message(&error, r));
                return 0;
        }

        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = sd_bus_call_method(
                        bus,
                        "org.freedesktop.machine1",
                        path,
                        "org.freedesktop.machine1.Machine",
                        "Terminate",
                        &error,
                        NULL,
                        NULL);
        if (r < 0) {
                log_debug("Failed to terminate machine: %s", bus_error_message(&error, r));
                return 0;
        }

        return 0;
}

static int reset_audit_loginuid(void) {
        _cleanup_free_ char *p = NULL;
        int r;

        if (arg_share_system)
                return 0;

        r = read_one_line_file("/proc/self/loginuid", &p);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read /proc/self/loginuid: %m");

        /* Already reset? */
        if (streq(p, "4294967295"))
                return 0;

        r = write_string_file("/proc/self/loginuid", "4294967295");
        if (r < 0) {
                log_error_errno(r,
                                "Failed to reset audit login UID. This probably means that your kernel is too\n"
                                "old and you have audit enabled. Note that the auditing subsystem is known to\n"
                                "be incompatible with containers on old kernels. Please make sure to upgrade\n"
                                "your kernel or to off auditing with 'audit=0' on the kernel command line before\n"
                                "using systemd-nspawn. Sleeping for 5s... (%m)");

                sleep(5);
        }

        return 0;
}

#define HOST_HASH_KEY SD_ID128_MAKE(1a,37,6f,c7,46,ec,45,0b,ad,a3,d5,31,06,60,5d,b1)
#define CONTAINER_HASH_KEY SD_ID128_MAKE(c3,c4,f9,19,b5,57,b2,1c,e6,cf,14,27,03,9c,ee,a2)
#define MACVLAN_HASH_KEY SD_ID128_MAKE(00,13,6d,bc,66,83,44,81,bb,0c,f9,51,1f,24,a6,6f)

static int generate_mac(struct ether_addr *mac, sd_id128_t hash_key, uint64_t idx) {
        uint8_t result[8];
        size_t l, sz;
        uint8_t *v, *i;
        int r;

        l = strlen(arg_machine);
        sz = sizeof(sd_id128_t) + l;
        if (idx > 0)
                sz += sizeof(idx);

        v = alloca(sz);

        /* fetch some persistent data unique to the host */
        r = sd_id128_get_machine((sd_id128_t*) v);
        if (r < 0)
                return r;

        /* combine with some data unique (on this host) to this
         * container instance */
        i = mempcpy(v + sizeof(sd_id128_t), arg_machine, l);
        if (idx > 0) {
                idx = htole64(idx);
                memcpy(i, &idx, sizeof(idx));
        }

        /* Let's hash the host machine ID plus the container name. We
         * use a fixed, but originally randomly created hash key here. */
        siphash24(result, v, sz, hash_key.bytes);

        assert_cc(ETH_ALEN <= sizeof(result));
        memcpy(mac->ether_addr_octet, result, ETH_ALEN);

        /* see eth_random_addr in the kernel */
        mac->ether_addr_octet[0] &= 0xfe;        /* clear multicast bit */
        mac->ether_addr_octet[0] |= 0x02;        /* set local assignment bit (IEEE802) */

        return 0;
}

static int setup_veth(pid_t pid, char iface_name[IFNAMSIZ], int *ifi) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        struct ether_addr mac_host, mac_container;
        int r, i;

        if (!arg_private_network)
                return 0;

        if (!arg_network_veth)
                return 0;

        /* Use two different interface name prefixes depending whether
         * we are in bridge mode or not. */
        snprintf(iface_name, IFNAMSIZ - 1, "%s-%s",
                 arg_network_bridge ? "vb" : "ve", arg_machine);

        r = generate_mac(&mac_container, CONTAINER_HASH_KEY, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to generate predictable MAC address for container side: %m");

        r = generate_mac(&mac_host, HOST_HASH_KEY, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to generate predictable MAC address for host side: %m");

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate netlink message: %m");

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, iface_name);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, &mac_host);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink MAC address: %m");

        r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "veth");
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_rtnl_message_open_container(m, VETH_INFO_PEER);
        if (r < 0)
                return log_error_errno(r, "Failed to open netlink container: %m");

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, "host0");
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name: %m");

        r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, &mac_container);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink MAC address: %m");

        r = sd_rtnl_message_append_u32(m, IFLA_NET_NS_PID, pid);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink namespace field: %m");

        r = sd_rtnl_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_rtnl_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_rtnl_message_close_container(m);
        if (r < 0)
                return log_error_errno(r, "Failed to close netlink container: %m");

        r = sd_rtnl_call(rtnl, m, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add new veth interfaces: %m");

        i = (int) if_nametoindex(iface_name);
        if (i <= 0)
                return log_error_errno(errno, "Failed to resolve interface %s: %m", iface_name);

        *ifi = i;

        return 0;
}

static int setup_bridge(const char veth_name[], int *ifi) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        int r, bridge;

        if (!arg_private_network)
                return 0;

        if (!arg_network_veth)
                return 0;

        if (!arg_network_bridge)
                return 0;

        bridge = (int) if_nametoindex(arg_network_bridge);
        if (bridge <= 0)
                return log_error_errno(errno, "Failed to resolve interface %s: %m", arg_network_bridge);

        *ifi = bridge;

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_SETLINK, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate netlink message: %m");

        r = sd_rtnl_message_link_set_flags(m, IFF_UP, IFF_UP);
        if (r < 0)
                return log_error_errno(r, "Failed to set IFF_UP flag: %m");

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, veth_name);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink interface name field: %m");

        r = sd_rtnl_message_append_u32(m, IFLA_MASTER, bridge);
        if (r < 0)
                return log_error_errno(r, "Failed to add netlink master field: %m");

        r = sd_rtnl_call(rtnl, m, 0, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to add veth interface to bridge: %m");

        return 0;
}

static int parse_interface(struct udev *udev, const char *name) {
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        char ifi_str[2 + DECIMAL_STR_MAX(int)];
        int ifi;

        ifi = (int) if_nametoindex(name);
        if (ifi <= 0)
                return log_error_errno(errno, "Failed to resolve interface %s: %m", name);

        sprintf(ifi_str, "n%i", ifi);
        d = udev_device_new_from_device_id(udev, ifi_str);
        if (!d)
                return log_error_errno(errno, "Failed to get udev device for interface %s: %m", name);

        if (udev_device_get_is_initialized(d) <= 0) {
                log_error("Network interface %s is not initialized yet.", name);
                return -EBUSY;
        }

        return ifi;
}

static int move_network_interfaces(pid_t pid) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        char **i;
        int r;

        if (!arg_private_network)
                return 0;

        if (strv_isempty(arg_network_interfaces))
                return 0;

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev.");
                return -ENOMEM;
        }

        STRV_FOREACH(i, arg_network_interfaces) {
                _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
                int ifi;

                ifi = parse_interface(udev, *i);
                if (ifi < 0)
                        return ifi;

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_SETLINK, ifi);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate netlink message: %m");

                r = sd_rtnl_message_append_u32(m, IFLA_NET_NS_PID, pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to append namespace PID to netlink message: %m");

                r = sd_rtnl_call(rtnl, m, 0, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to move interface %s to namespace: %m", *i);
        }

        return 0;
}

static int setup_macvlan(pid_t pid) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        unsigned idx = 0;
        char **i;
        int r;

        if (!arg_private_network)
                return 0;

        if (strv_isempty(arg_network_macvlan))
                return 0;

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev.");
                return -ENOMEM;
        }

        STRV_FOREACH(i, arg_network_macvlan) {
                _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
                _cleanup_free_ char *n = NULL;
                struct ether_addr mac;
                int ifi;

                ifi = parse_interface(udev, *i);
                if (ifi < 0)
                        return ifi;

                r = generate_mac(&mac, MACVLAN_HASH_KEY, idx++);
                if (r < 0)
                        return log_error_errno(r, "Failed to create MACVLAN MAC address: %m");

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate netlink message: %m");

                r = sd_rtnl_message_append_u32(m, IFLA_LINK, ifi);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface index: %m");

                n = strappend("mv-", *i);
                if (!n)
                        return log_oom();

                strshorten(n, IFNAMSIZ-1);

                r = sd_rtnl_message_append_string(m, IFLA_IFNAME, n);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface name: %m");

                r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, &mac);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink MAC address: %m");

                r = sd_rtnl_message_append_u32(m, IFLA_NET_NS_PID, pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink namespace field: %m");

                r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
                if (r < 0)
                        return log_error_errno(r, "Failed to open netlink container: %m");

                r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "macvlan");
                if (r < 0)
                        return log_error_errno(r, "Failed to open netlink container: %m");

                r = sd_rtnl_message_append_u32(m, IFLA_MACVLAN_MODE, MACVLAN_MODE_BRIDGE);
                if (r < 0)
                        return log_error_errno(r, "Failed to append macvlan mode: %m");

                r = sd_rtnl_message_close_container(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to close netlink container: %m");

                r = sd_rtnl_message_close_container(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to close netlink container: %m");

                r = sd_rtnl_call(rtnl, m, 0, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new macvlan interfaces: %m");
        }

        return 0;
}

static int setup_ipvlan(pid_t pid) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        char **i;
        int r;

        if (!arg_private_network)
                return 0;

        if (strv_isempty(arg_network_ipvlan))
                return 0;

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev.");
                return -ENOMEM;
        }

        STRV_FOREACH(i, arg_network_ipvlan) {
                _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
                _cleanup_free_ char *n = NULL;
                int ifi;

                ifi = parse_interface(udev, *i);
                if (ifi < 0)
                        return ifi;

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate netlink message: %m");

                r = sd_rtnl_message_append_u32(m, IFLA_LINK, ifi);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface index: %m");

                n = strappend("iv-", *i);
                if (!n)
                        return log_oom();

                strshorten(n, IFNAMSIZ-1);

                r = sd_rtnl_message_append_string(m, IFLA_IFNAME, n);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink interface name: %m");

                r = sd_rtnl_message_append_u32(m, IFLA_NET_NS_PID, pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to add netlink namespace field: %m");

                r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
                if (r < 0)
                        return log_error_errno(r, "Failed to open netlink container: %m");

                r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "ipvlan");
                if (r < 0)
                        return log_error_errno(r, "Failed to open netlink container: %m");

                r = sd_rtnl_message_append_u16(m, IFLA_IPVLAN_MODE, IPVLAN_MODE_L2);
                if (r < 0)
                        return log_error_errno(r, "Failed to add ipvlan mode: %m");

                r = sd_rtnl_message_close_container(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to close netlink container: %m");

                r = sd_rtnl_message_close_container(m);
                if (r < 0)
                        return log_error_errno(r, "Failed to close netlink container: %m");

                r = sd_rtnl_call(rtnl, m, 0, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add new ipvlan interfaces: %m");
        }

        return 0;
}

static int setup_seccomp(void) {

#ifdef HAVE_SECCOMP
        static const struct {
                uint64_t capability;
                int syscall_num;
        } blacklist[] = {
                { CAP_SYS_RAWIO,  SCMP_SYS(iopl)},
                { CAP_SYS_RAWIO,  SCMP_SYS(ioperm)},
                { CAP_SYS_BOOT,   SCMP_SYS(kexec_load)},
                { CAP_SYS_ADMIN,  SCMP_SYS(swapon)},
                { CAP_SYS_ADMIN,  SCMP_SYS(swapoff)},
                { CAP_SYS_ADMIN,  SCMP_SYS(open_by_handle_at)},
                { CAP_SYS_MODULE, SCMP_SYS(init_module)},
                { CAP_SYS_MODULE, SCMP_SYS(finit_module)},
                { CAP_SYS_MODULE, SCMP_SYS(delete_module)},
        };

        scmp_filter_ctx seccomp;
        unsigned i;
        int r;

        seccomp = seccomp_init(SCMP_ACT_ALLOW);
        if (!seccomp)
                return log_oom();

        r = seccomp_add_secondary_archs(seccomp);
        if (r < 0) {
                log_error_errno(r, "Failed to add secondary archs to seccomp filter: %m");
                goto finish;
        }

        for (i = 0; i < ELEMENTSOF(blacklist); i++) {
                if (arg_retain & (1ULL << blacklist[i].capability))
                        continue;

                r = seccomp_rule_add(seccomp, SCMP_ACT_ERRNO(EPERM), blacklist[i].syscall_num, 0);
                if (r == -EFAULT)
                        continue; /* unknown syscall */
                if (r < 0) {
                        log_error_errno(r, "Failed to block syscall: %m");
                        goto finish;
                }
        }


        /*
           Audit is broken in containers, much of the userspace audit
           hookup will fail if running inside a container. We don't
           care and just turn off creation of audit sockets.

           This will make socket(AF_NETLINK, *, NETLINK_AUDIT) fail
           with EAFNOSUPPORT which audit userspace uses as indication
           that audit is disabled in the kernel.
         */

        r = seccomp_rule_add(
                        seccomp,
                        SCMP_ACT_ERRNO(EAFNOSUPPORT),
                        SCMP_SYS(socket),
                        2,
                        SCMP_A0(SCMP_CMP_EQ, AF_NETLINK),
                        SCMP_A2(SCMP_CMP_EQ, NETLINK_AUDIT));
        if (r < 0) {
                log_error_errno(r, "Failed to add audit seccomp rule: %m");
                goto finish;
        }

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0) {
                log_error_errno(r, "Failed to unset NO_NEW_PRIVS: %m");
                goto finish;
        }

        r = seccomp_load(seccomp);
        if (r < 0)
                log_error_errno(r, "Failed to install seccomp audit filter: %m");

finish:
        seccomp_release(seccomp);
        return r;
#else
        return 0;
#endif

}

static int setup_propagate(const char *root) {
        const char *p, *q;

        (void) mkdir_p("/run/systemd/nspawn/", 0755);
        (void) mkdir_p("/run/systemd/nspawn/propagate", 0600);
        p = strjoina("/run/systemd/nspawn/propagate/", arg_machine);
        (void) mkdir_p(p, 0600);

        q = strjoina(root, "/run/systemd/nspawn/incoming");
        mkdir_parents(q, 0755);
        mkdir_p(q, 0600);

        if (mount(p, q, NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Failed to install propagation bind mount.");

        if (mount(NULL, q, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) < 0)
                return log_error_errno(errno, "Failed to make propagation mount read-only");

        return 0;
}

static int setup_image(char **device_path, int *loop_nr) {
        struct loop_info64 info = {
                .lo_flags = LO_FLAGS_AUTOCLEAR|LO_FLAGS_PARTSCAN
        };
        _cleanup_close_ int fd = -1, control = -1, loop = -1;
        _cleanup_free_ char* loopdev = NULL;
        struct stat st;
        int r, nr;

        assert(device_path);
        assert(loop_nr);
        assert(arg_image);

        fd = open(arg_image, O_CLOEXEC|(arg_read_only ? O_RDONLY : O_RDWR)|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open %s: %m", arg_image);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", arg_image);

        if (S_ISBLK(st.st_mode)) {
                char *p;

                p = strdup(arg_image);
                if (!p)
                        return log_oom();

                *device_path = p;

                *loop_nr = -1;

                r = fd;
                fd = -1;

                return r;
        }

        if (!S_ISREG(st.st_mode)) {
                log_error_errno(errno, "%s is not a regular file or block device: %m", arg_image);
                return -EINVAL;
        }

        control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (control < 0)
                return log_error_errno(errno, "Failed to open /dev/loop-control: %m");

        nr = ioctl(control, LOOP_CTL_GET_FREE);
        if (nr < 0)
                return log_error_errno(errno, "Failed to allocate loop device: %m");

        if (asprintf(&loopdev, "/dev/loop%i", nr) < 0)
                return log_oom();

        loop = open(loopdev, O_CLOEXEC|(arg_read_only ? O_RDONLY : O_RDWR)|O_NONBLOCK|O_NOCTTY);
        if (loop < 0)
                return log_error_errno(errno, "Failed to open loop device %s: %m", loopdev);

        if (ioctl(loop, LOOP_SET_FD, fd) < 0)
                return log_error_errno(errno, "Failed to set loopback file descriptor on %s: %m", loopdev);

        if (arg_read_only)
                info.lo_flags |= LO_FLAGS_READ_ONLY;

        if (ioctl(loop, LOOP_SET_STATUS64, &info) < 0)
                return log_error_errno(errno, "Failed to set loopback settings on %s: %m", loopdev);

        *device_path = loopdev;
        loopdev = NULL;

        *loop_nr = nr;

        r = loop;
        loop = -1;

        return r;
}

#define PARTITION_TABLE_BLURB \
        "Note that the disk image needs to either contain only a single MBR partition of\n" \
        "type 0x83 that is marked bootable, or a single GPT partition of type " \
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4 or follow\n" \
        "    http://www.freedesktop.org/wiki/Specifications/DiscoverablePartitionsSpec/\n" \
        "to be bootable with systemd-nspawn."

static int dissect_image(
                int fd,
                char **root_device, bool *root_device_rw,
                char **home_device, bool *home_device_rw,
                char **srv_device, bool *srv_device_rw,
                bool *secondary) {

#ifdef HAVE_BLKID
        int home_nr = -1, srv_nr = -1;
#ifdef GPT_ROOT_NATIVE
        int root_nr = -1;
#endif
#ifdef GPT_ROOT_SECONDARY
        int secondary_root_nr = -1;
#endif
        _cleanup_free_ char *home = NULL, *root = NULL, *secondary_root = NULL, *srv = NULL, *generic = NULL;
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        _cleanup_blkid_free_probe_ blkid_probe b = NULL;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        struct udev_list_entry *first, *item;
        bool home_rw = true, root_rw = true, secondary_root_rw = true, srv_rw = true, generic_rw = true;
        bool is_gpt, is_mbr, multiple_generic = false;
        const char *pttype = NULL;
        blkid_partlist pl;
        struct stat st;
        unsigned i;
        int r;

        assert(fd >= 0);
        assert(root_device);
        assert(home_device);
        assert(srv_device);
        assert(secondary);
        assert(arg_image);

        b = blkid_new_probe();
        if (!b)
                return log_oom();

        errno = 0;
        r = blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0) {
                if (errno == 0)
                        return log_oom();

                log_error_errno(errno, "Failed to set device on blkid probe: %m");
                return -errno;
        }

        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2 || r == 1) {
                log_error("Failed to identify any partition table on\n"
                          "    %s\n"
                          PARTITION_TABLE_BLURB, arg_image);
                return -EINVAL;
        } else if (r != 0) {
                if (errno == 0)
                        errno = EIO;
                log_error_errno(errno, "Failed to probe: %m");
                return -errno;
        }

        (void) blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);

        is_gpt = streq_ptr(pttype, "gpt");
        is_mbr = streq_ptr(pttype, "dos");

        if (!is_gpt && !is_mbr) {
                log_error("No GPT or MBR partition table discovered on\n"
                          "    %s\n"
                          PARTITION_TABLE_BLURB, arg_image);
                return -EINVAL;
        }

        errno = 0;
        pl = blkid_probe_get_partitions(b);
        if (!pl) {
                if (errno == 0)
                        return log_oom();

                log_error("Failed to list partitions of %s", arg_image);
                return -errno;
        }

        udev = udev_new();
        if (!udev)
                return log_oom();

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat block device: %m");

        d = udev_device_new_from_devnum(udev, 'b', st.st_rdev);
        if (!d)
                return log_oom();

        for (i = 0;; i++) {
                int n, m;

                if (i >= 10) {
                        log_error("Kernel partitions never appeared.");
                        return -ENXIO;
                }

                e = udev_enumerate_new(udev);
                if (!e)
                        return log_oom();

                r = udev_enumerate_add_match_parent(e, d);
                if (r < 0)
                        return log_oom();

                r = udev_enumerate_scan_devices(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan for partition devices of %s: %m", arg_image);

                /* Count the partitions enumerated by the kernel */
                n = 0;
                first = udev_enumerate_get_list_entry(e);
                udev_list_entry_foreach(item, first)
                        n++;

                /* Count the partitions enumerated by blkid */
                m = blkid_partlist_numof_partitions(pl);
                if (n == m + 1)
                        break;
                if (n > m + 1) {
                        log_error("blkid and kernel partition list do not match.");
                        return -EIO;
                }
                if (n < m + 1) {
                        unsigned j;

                        /* The kernel has probed fewer partitions than
                         * blkid? Maybe the kernel prober is still
                         * running or it got EBUSY because udev
                         * already opened the device. Let's reprobe
                         * the device, which is a synchronous call
                         * that waits until probing is complete. */

                        for (j = 0; j < 20; j++) {

                                r = ioctl(fd, BLKRRPART, 0);
                                if (r < 0)
                                        r = -errno;
                                if (r >= 0 || r != -EBUSY)
                                        break;

                                /* If something else has the device
                                 * open, such as an udev rule, the
                                 * ioctl will return EBUSY. Since
                                 * there's no way to wait until it
                                 * isn't busy anymore, let's just wait
                                 * a bit, and try again.
                                 *
                                 * This is really something they
                                 * should fix in the kernel! */

                                usleep(50 * USEC_PER_MSEC);
                        }

                        if (r < 0)
                                return log_error_errno(r, "Failed to reread partition table: %m");
                }

                e = udev_enumerate_unref(e);
        }

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                _cleanup_udev_device_unref_ struct udev_device *q;
                const char *node;
                unsigned long long flags;
                blkid_partition pp;
                dev_t qn;
                int nr;

                errno = 0;
                q = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                if (!q) {
                        if (!errno)
                                errno = ENOMEM;

                        log_error_errno(errno, "Failed to get partition device of %s: %m", arg_image);
                        return -errno;
                }

                qn = udev_device_get_devnum(q);
                if (major(qn) == 0)
                        continue;

                if (st.st_rdev == qn)
                        continue;

                node = udev_device_get_devnode(q);
                if (!node)
                        continue;

                pp = blkid_partlist_devno_to_partition(pl, qn);
                if (!pp)
                        continue;

                flags = blkid_partition_get_flags(pp);

                nr = blkid_partition_get_partno(pp);
                if (nr < 0)
                        continue;

                if (is_gpt) {
                        sd_id128_t type_id;
                        const char *stype;

                        if (flags & GPT_FLAG_NO_AUTO)
                                continue;

                        stype = blkid_partition_get_type_string(pp);
                        if (!stype)
                                continue;

                        if (sd_id128_from_string(stype, &type_id) < 0)
                                continue;

                        if (sd_id128_equal(type_id, GPT_HOME)) {

                                if (home && nr >= home_nr)
                                        continue;

                                home_nr = nr;
                                home_rw = !(flags & GPT_FLAG_READ_ONLY);

                                r = free_and_strdup(&home, node);
                                if (r < 0)
                                        return log_oom();

                        } else if (sd_id128_equal(type_id, GPT_SRV)) {

                                if (srv && nr >= srv_nr)
                                        continue;

                                srv_nr = nr;
                                srv_rw = !(flags & GPT_FLAG_READ_ONLY);

                                r = free_and_strdup(&srv, node);
                                if (r < 0)
                                        return log_oom();
                        }
#ifdef GPT_ROOT_NATIVE
                        else if (sd_id128_equal(type_id, GPT_ROOT_NATIVE)) {

                                if (root && nr >= root_nr)
                                        continue;

                                root_nr = nr;
                                root_rw = !(flags & GPT_FLAG_READ_ONLY);

                                r = free_and_strdup(&root, node);
                                if (r < 0)
                                        return log_oom();
                        }
#endif
#ifdef GPT_ROOT_SECONDARY
                        else if (sd_id128_equal(type_id, GPT_ROOT_SECONDARY)) {

                                if (secondary_root && nr >= secondary_root_nr)
                                        continue;

                                secondary_root_nr = nr;
                                secondary_root_rw = !(flags & GPT_FLAG_READ_ONLY);

                                r = free_and_strdup(&secondary_root, node);
                                if (r < 0)
                                        return log_oom();
                        }
#endif
                        else if (sd_id128_equal(type_id, GPT_LINUX_GENERIC)) {

                                if (generic)
                                        multiple_generic = true;
                                else {
                                        generic_rw = !(flags & GPT_FLAG_READ_ONLY);

                                        r = free_and_strdup(&generic, node);
                                        if (r < 0)
                                                return log_oom();
                                }
                        }

                } else if (is_mbr) {
                        int type;

                        if (flags != 0x80) /* Bootable flag */
                                continue;

                        type = blkid_partition_get_type(pp);
                        if (type != 0x83) /* Linux partition */
                                continue;

                        if (generic)
                                multiple_generic = true;
                        else {
                                generic_rw = true;

                                r = free_and_strdup(&root, node);
                                if (r < 0)
                                        return log_oom();
                        }
                }
        }

        if (root) {
                *root_device = root;
                root = NULL;

                *root_device_rw = root_rw;
                *secondary = false;
        } else if (secondary_root) {
                *root_device = secondary_root;
                secondary_root = NULL;

                *root_device_rw = secondary_root_rw;
                *secondary = true;
        } else if (generic) {

                /* There were no partitions with precise meanings
                 * around, but we found generic partitions. In this
                 * case, if there's only one, we can go ahead and boot
                 * it, otherwise we bail out, because we really cannot
                 * make any sense of it. */

                if (multiple_generic) {
                        log_error("Identified multiple bootable Linux partitions on\n"
                                  "    %s\n"
                                  PARTITION_TABLE_BLURB, arg_image);
                        return -EINVAL;
                }

                *root_device = generic;
                generic = NULL;

                *root_device_rw = generic_rw;
                *secondary = false;
        } else {
                log_error("Failed to identify root partition in disk image\n"
                          "    %s\n"
                          PARTITION_TABLE_BLURB, arg_image);
                return -EINVAL;
        }

        if (home) {
                *home_device = home;
                home = NULL;

                *home_device_rw = home_rw;
        }

        if (srv) {
                *srv_device = srv;
                srv = NULL;

                *srv_device_rw = srv_rw;
        }

        return 0;
#else
        log_error("--image= is not supported, compiled without blkid support.");
        return -EOPNOTSUPP;
#endif
}

static int mount_device(const char *what, const char *where, const char *directory, bool rw) {
#ifdef HAVE_BLKID
        _cleanup_blkid_free_probe_ blkid_probe b = NULL;
        const char *fstype, *p;
        int r;

        assert(what);
        assert(where);

        if (arg_read_only)
                rw = false;

        if (directory)
                p = strjoina(where, directory);
        else
                p = where;

        errno = 0;
        b = blkid_new_probe_from_filename(what);
        if (!b) {
                if (errno == 0)
                        return log_oom();
                log_error_errno(errno, "Failed to allocate prober for %s: %m", what);
                return -errno;
        }

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -1 || r == 1) {
                log_error("Cannot determine file system type of %s", what);
                return -EINVAL;
        } else if (r != 0) {
                if (errno == 0)
                        errno = EIO;
                log_error_errno(errno, "Failed to probe %s: %m", what);
                return -errno;
        }

        errno = 0;
        if (blkid_probe_lookup_value(b, "TYPE", &fstype, NULL) < 0) {
                if (errno == 0)
                        errno = EINVAL;
                log_error("Failed to determine file system type of %s", what);
                return -errno;
        }

        if (streq(fstype, "crypto_LUKS")) {
                log_error("nspawn currently does not support LUKS disk images.");
                return -EOPNOTSUPP;
        }

        if (mount(what, p, fstype, MS_NODEV|(rw ? 0 : MS_RDONLY), NULL) < 0)
                return log_error_errno(errno, "Failed to mount %s: %m", what);

        return 0;
#else
        log_error("--image= is not supported, compiled without blkid support.");
        return -EOPNOTSUPP;
#endif
}

static int mount_devices(
                const char *where,
                const char *root_device, bool root_device_rw,
                const char *home_device, bool home_device_rw,
                const char *srv_device, bool srv_device_rw) {
        int r;

        assert(where);

        if (root_device) {
                r = mount_device(root_device, arg_directory, NULL, root_device_rw);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount root directory: %m");
        }

        if (home_device) {
                r = mount_device(home_device, arg_directory, "/home", home_device_rw);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount home directory: %m");
        }

        if (srv_device) {
                r = mount_device(srv_device, arg_directory, "/srv", srv_device_rw);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount server data directory: %m");
        }

        return 0;
}

static void loop_remove(int nr, int *image_fd) {
        _cleanup_close_ int control = -1;
        int r;

        if (nr < 0)
                return;

        if (image_fd && *image_fd >= 0) {
                r = ioctl(*image_fd, LOOP_CLR_FD);
                if (r < 0)
                        log_debug_errno(errno, "Failed to close loop image: %m");
                *image_fd = safe_close(*image_fd);
        }

        control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (control < 0) {
                log_warning_errno(errno, "Failed to open /dev/loop-control: %m");
                return;
        }

        r = ioctl(control, LOOP_CTL_REMOVE, nr);
        if (r < 0)
                log_debug_errno(errno, "Failed to remove loop %d: %m", nr);
}

static int spawn_getent(const char *database, const char *key, pid_t *rpid) {
        int pipe_fds[2];
        pid_t pid;

        assert(database);
        assert(key);
        assert(rpid);

        if (pipe2(pipe_fds, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate pipe: %m");

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork getent child: %m");
        else if (pid == 0) {
                int nullfd;
                char *empty_env = NULL;

                if (dup3(pipe_fds[1], STDOUT_FILENO, 0) < 0)
                        _exit(EXIT_FAILURE);

                if (pipe_fds[0] > 2)
                        safe_close(pipe_fds[0]);
                if (pipe_fds[1] > 2)
                        safe_close(pipe_fds[1]);

                nullfd = open("/dev/null", O_RDWR);
                if (nullfd < 0)
                        _exit(EXIT_FAILURE);

                if (dup3(nullfd, STDIN_FILENO, 0) < 0)
                        _exit(EXIT_FAILURE);

                if (dup3(nullfd, STDERR_FILENO, 0) < 0)
                        _exit(EXIT_FAILURE);

                if (nullfd > 2)
                        safe_close(nullfd);

                reset_all_signal_handlers();
                close_all_fds(NULL, 0);

                execle("/usr/bin/getent", "getent", database, key, NULL, &empty_env);
                execle("/bin/getent", "getent", database, key, NULL, &empty_env);
                _exit(EXIT_FAILURE);
        }

        pipe_fds[1] = safe_close(pipe_fds[1]);

        *rpid = pid;

        return pipe_fds[0];
}

static int change_uid_gid(char **_home) {
        char line[LINE_MAX], *x, *u, *g, *h;
        const char *word, *state;
        _cleanup_free_ uid_t *uids = NULL;
        _cleanup_free_ char *home = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_close_ int fd = -1;
        unsigned n_uids = 0;
        size_t sz = 0, l;
        uid_t uid;
        gid_t gid;
        pid_t pid;
        int r;

        assert(_home);

        if (!arg_user || streq(arg_user, "root") || streq(arg_user, "0")) {
                /* Reset everything fully to 0, just in case */

                if (setgroups(0, NULL) < 0)
                        return log_error_errno(errno, "setgroups() failed: %m");

                if (setresgid(0, 0, 0) < 0)
                        return log_error_errno(errno, "setregid() failed: %m");

                if (setresuid(0, 0, 0) < 0)
                        return log_error_errno(errno, "setreuid() failed: %m");

                *_home = NULL;
                return 0;
        }

        /* First, get user credentials */
        fd = spawn_getent("passwd", arg_user, &pid);
        if (fd < 0)
                return fd;

        f = fdopen(fd, "r");
        if (!f)
                return log_oom();
        fd = -1;

        if (!fgets(line, sizeof(line), f)) {

                if (!ferror(f)) {
                        log_error("Failed to resolve user %s.", arg_user);
                        return -ESRCH;
                }

                log_error_errno(errno, "Failed to read from getent: %m");
                return -errno;
        }

        truncate_nl(line);

        wait_for_terminate_and_warn("getent passwd", pid, true);

        x = strchr(line, ':');
        if (!x) {
                log_error("/etc/passwd entry has invalid user field.");
                return -EIO;
        }

        u = strchr(x+1, ':');
        if (!u) {
                log_error("/etc/passwd entry has invalid password field.");
                return -EIO;
        }

        u++;
        g = strchr(u, ':');
        if (!g) {
                log_error("/etc/passwd entry has invalid UID field.");
                return -EIO;
        }

        *g = 0;
        g++;
        x = strchr(g, ':');
        if (!x) {
                log_error("/etc/passwd entry has invalid GID field.");
                return -EIO;
        }

        *x = 0;
        h = strchr(x+1, ':');
        if (!h) {
                log_error("/etc/passwd entry has invalid GECOS field.");
                return -EIO;
        }

        h++;
        x = strchr(h, ':');
        if (!x) {
                log_error("/etc/passwd entry has invalid home directory field.");
                return -EIO;
        }

        *x = 0;

        r = parse_uid(u, &uid);
        if (r < 0) {
                log_error("Failed to parse UID of user.");
                return -EIO;
        }

        r = parse_gid(g, &gid);
        if (r < 0) {
                log_error("Failed to parse GID of user.");
                return -EIO;
        }

        home = strdup(h);
        if (!home)
                return log_oom();

        /* Second, get group memberships */
        fd = spawn_getent("initgroups", arg_user, &pid);
        if (fd < 0)
                return fd;

        fclose(f);
        f = fdopen(fd, "r");
        if (!f)
                return log_oom();
        fd = -1;

        if (!fgets(line, sizeof(line), f)) {
                if (!ferror(f)) {
                        log_error("Failed to resolve user %s.", arg_user);
                        return -ESRCH;
                }

                log_error_errno(errno, "Failed to read from getent: %m");
                return -errno;
        }

        truncate_nl(line);

        wait_for_terminate_and_warn("getent initgroups", pid, true);

        /* Skip over the username and subsequent separator whitespace */
        x = line;
        x += strcspn(x, WHITESPACE);
        x += strspn(x, WHITESPACE);

        FOREACH_WORD(word, l, x, state) {
                char c[l+1];

                memcpy(c, word, l);
                c[l] = 0;

                if (!GREEDY_REALLOC(uids, sz, n_uids+1))
                        return log_oom();

                r = parse_uid(c, &uids[n_uids++]);
                if (r < 0) {
                        log_error("Failed to parse group data from getent.");
                        return -EIO;
                }
        }

        r = mkdir_parents(home, 0775);
        if (r < 0)
                return log_error_errno(r, "Failed to make home root directory: %m");

        r = mkdir_safe(home, 0755, uid, gid);
        if (r < 0 && r != -EEXIST)
                return log_error_errno(r, "Failed to make home directory: %m");

        fchown(STDIN_FILENO, uid, gid);
        fchown(STDOUT_FILENO, uid, gid);
        fchown(STDERR_FILENO, uid, gid);

        if (setgroups(n_uids, uids) < 0)
                return log_error_errno(errno, "Failed to set auxiliary groups: %m");

        if (setresgid(gid, gid, gid) < 0)
                return log_error_errno(errno, "setregid() failed: %m");

        if (setresuid(uid, uid, uid) < 0)
                return log_error_errno(errno, "setreuid() failed: %m");

        if (_home) {
                *_home = home;
                home = NULL;
        }

        return 0;
}

/*
 * Return values:
 * < 0 : wait_for_terminate() failed to get the state of the
 *       container, the container was terminated by a signal, or
 *       failed for an unknown reason.  No change is made to the
 *       container argument.
 * > 0 : The program executed in the container terminated with an
 *       error.  The exit code of the program executed in the
 *       container is returned.  The container argument has been set
 *       to CONTAINER_TERMINATED.
 *   0 : The container is being rebooted, has been shut down or exited
 *       successfully.  The container argument has been set to either
 *       CONTAINER_TERMINATED or CONTAINER_REBOOTED.
 *
 * That is, success is indicated by a return value of zero, and an
 * error is indicated by a non-zero value.
 */
static int wait_for_container(pid_t pid, ContainerStatus *container) {
        siginfo_t status;
        int r;

        r = wait_for_terminate(pid, &status);
        if (r < 0)
                return log_warning_errno(r, "Failed to wait for container: %m");

        switch (status.si_code) {

        case CLD_EXITED:
                if (status.si_status == 0) {
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s exited successfully.", arg_machine);

                } else
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s failed with error code %i.", arg_machine, status.si_status);

                *container = CONTAINER_TERMINATED;
                return status.si_status;

        case CLD_KILLED:
                if (status.si_status == SIGINT) {

                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s has been shut down.", arg_machine);
                        *container = CONTAINER_TERMINATED;
                        return 0;

                } else if (status.si_status == SIGHUP) {

                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s is being rebooted.", arg_machine);
                        *container = CONTAINER_REBOOTED;
                        return 0;
                }

                /* CLD_KILLED fallthrough */

        case CLD_DUMPED:
                log_error("Container %s terminated by signal %s.", arg_machine, signal_to_string(status.si_status));
                return -EIO;

        default:
                log_error("Container %s failed due to unknown reason.", arg_machine);
                return -EIO;
        }

        return r;
}

static void nop_handler(int sig) {}

static int on_orderly_shutdown(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        pid_t pid;

        pid = PTR_TO_UINT32(userdata);
        if (pid > 0) {
                if (kill(pid, arg_kill_signal) >= 0) {
                        log_info("Trying to halt container. Send SIGTERM again to trigger immediate termination.");
                        sd_event_source_set_userdata(s, NULL);
                        return 0;
                }
        }

        sd_event_exit(sd_event_source_get_event(s), 0);
        return 0;
}

static int determine_names(void) {
        int r;

        if (!arg_image && !arg_directory) {
                if (arg_machine) {
                        _cleanup_(image_unrefp) Image *i = NULL;

                        r = image_find(arg_machine, &i);
                        if (r < 0)
                                return log_error_errno(r, "Failed to find image for machine '%s': %m", arg_machine);
                        else if (r == 0) {
                                log_error("No image for machine '%s': %m", arg_machine);
                                return -ENOENT;
                        }

                        if (i->type == IMAGE_RAW)
                                r = set_sanitized_path(&arg_image, i->path);
                        else
                                r = set_sanitized_path(&arg_directory, i->path);
                        if (r < 0)
                                return log_error_errno(r, "Invalid image directory: %m");

                        if (!arg_ephemeral)
                                arg_read_only = arg_read_only || i->read_only;
                } else
                        arg_directory = get_current_dir_name();

                if (!arg_directory && !arg_machine) {
                        log_error("Failed to determine path, please use -D or -i.");
                        return -EINVAL;
                }
        }

        if (!arg_machine) {
                if (arg_directory && path_equal(arg_directory, "/"))
                        arg_machine = gethostname_malloc();
                else
                        arg_machine = strdup(basename(arg_image ?: arg_directory));

                if (!arg_machine)
                        return log_oom();

                hostname_cleanup(arg_machine, false);
                if (!machine_name_is_valid(arg_machine)) {
                        log_error("Failed to determine machine name automatically, please use -M.");
                        return -EINVAL;
                }

                if (arg_ephemeral) {
                        char *b;

                        /* Add a random suffix when this is an
                         * ephemeral machine, so that we can run many
                         * instances at once without manually having
                         * to specify -M each time. */

                        if (asprintf(&b, "%s-%016" PRIx64, arg_machine, random_u64()) < 0)
                                return log_oom();

                        free(arg_machine);
                        arg_machine = b;
                }
        }

        return 0;
}

static int determine_uid_shift(void) {
        int r;

        if (!arg_userns)
                return 0;

        if (arg_uid_shift == UID_INVALID) {
                struct stat st;

                r = stat(arg_directory, &st);
                if (r < 0)
                        return log_error_errno(errno, "Failed to determine UID base of %s: %m", arg_directory);

                arg_uid_shift = st.st_uid & UINT32_C(0xffff0000);

                if (arg_uid_shift != (st.st_gid & UINT32_C(0xffff0000))) {
                        log_error("UID and GID base of %s don't match.", arg_directory);
                        return -EINVAL;
                }

                arg_uid_range = UINT32_C(0x10000);
        }

        if (arg_uid_shift > (uid_t) -1 - arg_uid_range) {
                log_error("UID base too high for UID range.");
                return -EINVAL;
        }

        log_info("Using user namespaces with base " UID_FMT " and range " UID_FMT ".", arg_uid_shift, arg_uid_range);
        return 0;
}

int main(int argc, char *argv[]) {

        _cleanup_free_ char *device_path = NULL, *root_device = NULL, *home_device = NULL, *srv_device = NULL, *console = NULL;
        bool root_device_rw = true, home_device_rw = true, srv_device_rw = true;
        _cleanup_close_ int master = -1, image_fd = -1;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        int r, n_fd_passed, loop_nr = -1;
        char veth_name[IFNAMSIZ];
        bool secondary = false, remove_subvol = false;
        sigset_t mask, mask_chld;
        pid_t pid = 0;
        int ret = EXIT_SUCCESS;
        union in_addr_union exposed = {};
        _cleanup_release_lock_file_ LockFile tree_global_lock = LOCK_FILE_INIT, tree_local_lock = LOCK_FILE_INIT;
        bool interactive;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = determine_names();
        if (r < 0)
                goto finish;

        if (geteuid() != 0) {
                log_error("Need to be root.");
                r = -EPERM;
                goto finish;
        }

        log_close();
        n_fd_passed = sd_listen_fds(false);
        if (n_fd_passed > 0) {
                r = fdset_new_listen_fds(&fds, false);
                if (r < 0) {
                        log_error_errno(r, "Failed to collect file descriptors: %m");
                        goto finish;
                }
        }
        fdset_close_others(fds);
        log_open();

        if (arg_directory) {
                assert(!arg_image);

                if (path_equal(arg_directory, "/") && !arg_ephemeral) {
                        log_error("Spawning container on root directory is not supported. Consider using --ephemeral.");
                        r = -EINVAL;
                        goto finish;
                }

                if (arg_ephemeral) {
                        _cleanup_free_ char *np = NULL;

                        /* If the specified path is a mount point we
                         * generate the new snapshot immediately
                         * inside it under a random name. However if
                         * the specified is not a mount point we
                         * create the new snapshot in the parent
                         * directory, just next to it. */
                        r = path_is_mount_point(arg_directory, false);
                        if (r < 0) {
                                log_error_errno(r, "Failed to determine whether directory %s is mount point: %m", arg_directory);
                                goto finish;
                        }
                        if (r > 0)
                                r = tempfn_random_child(arg_directory, &np);
                        else
                                r = tempfn_random(arg_directory, &np);
                        if (r < 0) {
                                log_error_errno(r, "Failed to generate name for snapshot: %m");
                                goto finish;
                        }

                        r = image_path_lock(np, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r < 0) {
                                log_error_errno(r, "Failed to lock %s: %m", np);
                                goto finish;
                        }

                        r = btrfs_subvol_snapshot(arg_directory, np, (arg_read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) | BTRFS_SNAPSHOT_FALLBACK_COPY | BTRFS_SNAPSHOT_RECURSIVE);
                        if (r < 0) {
                                log_error_errno(r, "Failed to create snapshot %s from %s: %m", np, arg_directory);
                                goto finish;
                        }

                        free(arg_directory);
                        arg_directory = np;
                        np = NULL;

                        remove_subvol = true;

                } else {
                        r = image_path_lock(arg_directory, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r == -EBUSY) {
                                log_error_errno(r, "Directory tree %s is currently busy.", arg_directory);
                                goto finish;
                        }
                        if (r < 0) {
                                log_error_errno(r, "Failed to lock %s: %m", arg_directory);
                                return r;
                        }

                        if (arg_template) {
                                r = btrfs_subvol_snapshot(arg_template, arg_directory, (arg_read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) | BTRFS_SNAPSHOT_FALLBACK_COPY | BTRFS_SNAPSHOT_RECURSIVE);
                                if (r == -EEXIST) {
                                        if (!arg_quiet)
                                                log_info("Directory %s already exists, not populating from template %s.", arg_directory, arg_template);
                                } else if (r < 0) {
                                        log_error_errno(r, "Couldn't create snapshot %s from %s: %m", arg_directory, arg_template);
                                        goto finish;
                                } else {
                                        if (!arg_quiet)
                                                log_info("Populated %s from template %s.", arg_directory, arg_template);
                                }
                        }
                }

                if (arg_boot) {
                        if (path_is_os_tree(arg_directory) <= 0) {
                                log_error("Directory %s doesn't look like an OS root directory (os-release file is missing). Refusing.", arg_directory);
                                r = -EINVAL;
                                goto finish;
                        }
                } else {
                        const char *p;

                        p = strjoina(arg_directory,
                                       argc > optind && path_is_absolute(argv[optind]) ? argv[optind] : "/usr/bin/");
                        if (access(p, F_OK) < 0) {
                                log_error("Directory %s lacks the binary to execute or doesn't look like a binary tree. Refusing.", arg_directory);
                                r = -EINVAL;
                                goto finish;
                        }
                }

        } else {
                char template[] = "/tmp/nspawn-root-XXXXXX";

                assert(arg_image);
                assert(!arg_template);

                r = image_path_lock(arg_image, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                if (r == -EBUSY) {
                        r = log_error_errno(r, "Disk image %s is currently busy.", arg_image);
                        goto finish;
                }
                if (r < 0) {
                        r = log_error_errno(r, "Failed to create image lock: %m");
                        goto finish;
                }

                if (!mkdtemp(template)) {
                        log_error_errno(errno, "Failed to create temporary directory: %m");
                        r = -errno;
                        goto finish;
                }

                arg_directory = strdup(template);
                if (!arg_directory) {
                        r = log_oom();
                        goto finish;
                }

                image_fd = setup_image(&device_path, &loop_nr);
                if (image_fd < 0) {
                        r = image_fd;
                        goto finish;
                }

                r = dissect_image(image_fd,
                                  &root_device, &root_device_rw,
                                  &home_device, &home_device_rw,
                                  &srv_device, &srv_device_rw,
                                  &secondary);
                if (r < 0)
                        goto finish;
        }

        r = determine_uid_shift();
        if (r < 0)
                goto finish;

        interactive = isatty(STDIN_FILENO) > 0 && isatty(STDOUT_FILENO) > 0;

        master = posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NDELAY);
        if (master < 0) {
                r = log_error_errno(errno, "Failed to acquire pseudo tty: %m");
                goto finish;
        }

        r = ptsname_malloc(master, &console);
        if (r < 0) {
                r = log_error_errno(r, "Failed to determine tty name: %m");
                goto finish;
        }

        if (unlockpt(master) < 0) {
                r = log_error_errno(errno, "Failed to unlock tty: %m");
                goto finish;
        }

        if (!arg_quiet)
                log_info("Spawning container %s on %s.\nPress ^] three times within 1s to kill container.",
                         arg_machine, arg_image ?: arg_directory);

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGCHLD, SIGWINCH, SIGTERM, SIGINT, -1);
        assert_se(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);

        assert_se(sigemptyset(&mask_chld) == 0);
        assert_se(sigaddset(&mask_chld, SIGCHLD) == 0);

        for (;;) {
                _cleanup_close_pair_ int kmsg_socket_pair[2] = { -1, -1 }, rtnl_socket_pair[2] = { -1, -1 };
                ContainerStatus container_status;
                _cleanup_(barrier_destroy) Barrier barrier = BARRIER_NULL;
                struct sigaction sa = {
                        .sa_handler = nop_handler,
                        .sa_flags = SA_NOCLDSTOP,
                };

                r = barrier_create(&barrier);
                if (r < 0) {
                        log_error_errno(r, "Cannot initialize IPC barrier: %m");
                        goto finish;
                }

                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, kmsg_socket_pair) < 0) {
                        r = log_error_errno(errno, "Failed to create kmsg socket pair: %m");
                        goto finish;
                }

                if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, rtnl_socket_pair) < 0) {
                        r = log_error_errno(errno, "Failed to create rtnl socket pair: %m");
                        goto finish;
                }

                /* Child can be killed before execv(), so handle SIGCHLD
                 * in order to interrupt parent's blocking calls and
                 * give it a chance to call wait() and terminate. */
                r = sigprocmask(SIG_UNBLOCK, &mask_chld, NULL);
                if (r < 0) {
                        r = log_error_errno(errno, "Failed to change the signal mask: %m");
                        goto finish;
                }

                r = sigaction(SIGCHLD, &sa, NULL);
                if (r < 0) {
                        r = log_error_errno(errno, "Failed to install SIGCHLD handler: %m");
                        goto finish;
                }

                pid = raw_clone(SIGCHLD|CLONE_NEWNS|
                                (arg_share_system ? 0 : CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS)|
                                (arg_private_network ? CLONE_NEWNET : 0), NULL);
                if (pid < 0) {
                        if (errno == EINVAL)
                                r = log_error_errno(errno, "clone() failed, do you have namespace support enabled in your kernel? (You need UTS, IPC, PID and NET namespacing built in): %m");
                        else
                                r = log_error_errno(errno, "clone() failed: %m");

                        goto finish;
                }

                if (pid == 0) {
                        /* child */
                        _cleanup_free_ char *home = NULL;
                        unsigned n_env = 2;
                        const char *envp[] = {
                                "PATH=" DEFAULT_PATH_SPLIT_USR,
                                "container=systemd-nspawn", /* LXC sets container=lxc, so follow the scheme here */
                                NULL, /* TERM */
                                NULL, /* HOME */
                                NULL, /* USER */
                                NULL, /* LOGNAME */
                                NULL, /* container_uuid */
                                NULL, /* LISTEN_FDS */
                                NULL, /* LISTEN_PID */
                                NULL
                        };
                        char **env_use;

                        barrier_set_role(&barrier, BARRIER_CHILD);

                        envp[n_env] = strv_find_prefix(environ, "TERM=");
                        if (envp[n_env])
                                n_env ++;

                        master = safe_close(master);

                        kmsg_socket_pair[0] = safe_close(kmsg_socket_pair[0]);
                        rtnl_socket_pair[0] = safe_close(rtnl_socket_pair[0]);

                        reset_all_signal_handlers();
                        reset_signal_mask();

                        if (interactive) {
                                close_nointr(STDIN_FILENO);
                                close_nointr(STDOUT_FILENO);
                                close_nointr(STDERR_FILENO);

                                r = open_terminal(console, O_RDWR);
                                if (r != STDIN_FILENO) {
                                        if (r >= 0) {
                                                safe_close(r);
                                                r = -EINVAL;
                                        }

                                        log_error_errno(r, "Failed to open console: %m");
                                        _exit(EXIT_FAILURE);
                                }

                                if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO ||
                                    dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
                                        log_error_errno(errno, "Failed to duplicate console: %m");
                                        _exit(EXIT_FAILURE);
                                }
                        }

                        if (setsid() < 0) {
                                log_error_errno(errno, "setsid() failed: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (reset_audit_loginuid() < 0)
                                _exit(EXIT_FAILURE);

                        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
                                log_error_errno(errno, "PR_SET_PDEATHSIG failed: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (arg_private_network)
                                loopback_setup();

                        /* Mark everything as slave, so that we still
                         * receive mounts from the real root, but don't
                         * propagate mounts to the real root. */
                        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
                                log_error_errno(errno, "MS_SLAVE|MS_REC failed: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (mount_devices(arg_directory,
                                          root_device, root_device_rw,
                                          home_device, home_device_rw,
                                          srv_device, srv_device_rw) < 0)
                                _exit(EXIT_FAILURE);

                        /* Turn directory into bind mount */
                        if (mount(arg_directory, arg_directory, NULL, MS_BIND|MS_REC, NULL) < 0) {
                                log_error_errno(errno, "Failed to make bind mount: %m");
                                _exit(EXIT_FAILURE);
                        }

                        r = setup_volatile(arg_directory);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        if (setup_volatile_state(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        r = base_filesystem_create(arg_directory);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        if (arg_read_only) {
                                r = bind_remount_recursive(arg_directory, true);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to make tree read-only: %m");
                                        _exit(EXIT_FAILURE);
                                }
                        }

                        if (mount_all(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        if (copy_devnodes(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        if (setup_ptmx(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        dev_setup(arg_directory);

                        if (setup_propagate(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        if (setup_seccomp() < 0)
                                _exit(EXIT_FAILURE);

                        if (setup_dev_console(arg_directory, console) < 0)
                                _exit(EXIT_FAILURE);

                        if (setup_kmsg(arg_directory, kmsg_socket_pair[1]) < 0)
                                _exit(EXIT_FAILURE);
                        kmsg_socket_pair[1] = safe_close(kmsg_socket_pair[1]);

                        if (send_rtnl(rtnl_socket_pair[1]) < 0)
                                _exit(EXIT_FAILURE);
                        rtnl_socket_pair[1] = safe_close(rtnl_socket_pair[1]);

                        /* Tell the parent that we are ready, and that
                         * it can cgroupify us to that we lack access
                         * to certain devices and resources. */
                        (void) barrier_place(&barrier); /* #1 */

                        if (setup_boot_id(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        if (setup_timezone(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        if (setup_resolv_conf(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        if (setup_journal(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        if (mount_binds(arg_directory, arg_bind, false) < 0)
                                _exit(EXIT_FAILURE);

                        if (mount_binds(arg_directory, arg_bind_ro, true) < 0)
                                _exit(EXIT_FAILURE);

                        if (mount_tmpfs(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        /* Wait until we are cgroup-ified, so that we
                         * can mount the right cgroup path writable */
                        (void) barrier_place_and_sync(&barrier); /* #2 */

                        if (mount_cgroup(arg_directory) < 0)
                                _exit(EXIT_FAILURE);

                        if (chdir(arg_directory) < 0) {
                                log_error_errno(errno, "chdir(%s) failed: %m", arg_directory);
                                _exit(EXIT_FAILURE);
                        }

                        if (mount(arg_directory, "/", NULL, MS_MOVE, NULL) < 0) {
                                log_error_errno(errno, "mount(MS_MOVE) failed: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (chroot(".") < 0) {
                                log_error_errno(errno, "chroot() failed: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (chdir("/") < 0) {
                                log_error_errno(errno, "chdir() failed: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (arg_userns) {
                                if (unshare(CLONE_NEWUSER) < 0) {
                                        log_error_errno(errno, "unshare(CLONE_NEWUSER) failed: %m");
                                        _exit(EXIT_FAILURE);
                                }

                                /* Tell the parent, that it now can
                                 * write the UID map. */
                                (void) barrier_place(&barrier); /* #3 */

                                /* Wait until the parent wrote the UID
                                 * map */
                                (void) barrier_place_and_sync(&barrier); /* #4 */
                        }

                        umask(0022);

                        if (drop_capabilities() < 0) {
                                log_error_errno(errno, "drop_capabilities() failed: %m");
                                _exit(EXIT_FAILURE);
                        }

                        setup_hostname();

                        if (arg_personality != 0xffffffffLU) {
                                if (personality(arg_personality) < 0) {
                                        log_error_errno(errno, "personality() failed: %m");
                                        _exit(EXIT_FAILURE);
                                }
                        } else if (secondary) {
                                if (personality(PER_LINUX32) < 0) {
                                        log_error_errno(errno, "personality() failed: %m");
                                        _exit(EXIT_FAILURE);
                                }
                        }

#ifdef HAVE_SELINUX
                        if (arg_selinux_context)
                                if (setexeccon((security_context_t) arg_selinux_context) < 0) {
                                        log_error_errno(errno, "setexeccon(\"%s\") failed: %m", arg_selinux_context);
                                        _exit(EXIT_FAILURE);
                                }
#endif

                        r = change_uid_gid(&home);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        if ((asprintf((char**)(envp + n_env++), "HOME=%s", home ? home: "/root") < 0) ||
                            (asprintf((char**)(envp + n_env++), "USER=%s", arg_user ? arg_user : "root") < 0) ||
                            (asprintf((char**)(envp + n_env++), "LOGNAME=%s", arg_user ? arg_user : "root") < 0)) {
                                log_oom();
                                _exit(EXIT_FAILURE);
                        }

                        if (!sd_id128_equal(arg_uuid, SD_ID128_NULL)) {
                                char as_uuid[37];

                                if (asprintf((char**)(envp + n_env++), "container_uuid=%s", id128_format_as_uuid(arg_uuid, as_uuid)) < 0) {
                                        log_oom();
                                        _exit(EXIT_FAILURE);
                                }
                        }

                        if (fdset_size(fds) > 0) {
                                r = fdset_cloexec(fds, false);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to unset O_CLOEXEC for file descriptors.");
                                        _exit(EXIT_FAILURE);
                                }

                                if ((asprintf((char **)(envp + n_env++), "LISTEN_FDS=%u", n_fd_passed) < 0) ||
                                    (asprintf((char **)(envp + n_env++), "LISTEN_PID=1") < 0)) {
                                        log_oom();
                                        _exit(EXIT_FAILURE);
                                }
                        }

                        if (!strv_isempty(arg_setenv)) {
                                char **n;

                                n = strv_env_merge(2, envp, arg_setenv);
                                if (!n) {
                                        log_oom();
                                        _exit(EXIT_FAILURE);
                                }

                                env_use = n;
                        } else
                                env_use = (char**) envp;

                        /* Let the parent know that we are ready and
                         * wait until the parent is ready with the
                         * setup, too... */
                        (void) barrier_place_and_sync(&barrier); /* #5 */

                        if (arg_boot) {
                                char **a;
                                size_t l;

                                /* Automatically search for the init system */

                                l = 1 + argc - optind;
                                a = newa(char*, l + 1);
                                memcpy(a + 1, argv + optind, l * sizeof(char*));

                                a[0] = (char*) "/usr/lib/systemd/systemd";
                                execve(a[0], a, env_use);

                                a[0] = (char*) "/lib/systemd/systemd";
                                execve(a[0], a, env_use);

                                a[0] = (char*) "/sbin/init";
                                execve(a[0], a, env_use);
                        } else if (argc > optind)
                                execvpe(argv[optind], argv + optind, env_use);
                        else {
                                chdir(home ? home : "/root");
                                execle("/bin/bash", "-bash", NULL, env_use);
                                execle("/bin/sh", "-sh", NULL, env_use);
                        }

                        log_error_errno(errno, "execv() failed: %m");
                        _exit(EXIT_FAILURE);
                }

                barrier_set_role(&barrier, BARRIER_PARENT);
                fdset_free(fds);
                fds = NULL;

                kmsg_socket_pair[1] = safe_close(kmsg_socket_pair[1]);
                rtnl_socket_pair[1] = safe_close(rtnl_socket_pair[1]);

                (void) barrier_place(&barrier); /* #1 */

                /* Wait for the most basic Child-setup to be done,
                 * before we add hardware to it, and place it in a
                 * cgroup. */
                if (barrier_sync(&barrier)) { /* #1 */
                        int ifi = 0;

                        r = move_network_interfaces(pid);
                        if (r < 0)
                                goto finish;

                        r = setup_veth(pid, veth_name, &ifi);
                        if (r < 0)
                                goto finish;

                        r = setup_bridge(veth_name, &ifi);
                        if (r < 0)
                                goto finish;

                        r = setup_macvlan(pid);
                        if (r < 0)
                                goto finish;

                        r = setup_ipvlan(pid);
                        if (r < 0)
                                goto finish;

                        r = register_machine(pid, ifi);
                        if (r < 0)
                                goto finish;

                        /* Notify the child that the parent is ready with all
                         * its setup, and that the child can now hand over
                         * control to the code to run inside the container. */
                        (void) barrier_place(&barrier); /* #2 */

                        if (arg_userns) {
                                char uid_map[strlen("/proc//uid_map") + DECIMAL_STR_MAX(uid_t) + 1], line[DECIMAL_STR_MAX(uid_t)*3+3+1];

                                (void) barrier_place_and_sync(&barrier); /* #3 */

                                xsprintf(uid_map, "/proc/" PID_FMT "/uid_map", pid);
                                xsprintf(line, UID_FMT " " UID_FMT " " UID_FMT "\n", 0, arg_uid_shift, arg_uid_range);
                                r = write_string_file(uid_map, line);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to write UID map: %m");
                                        goto finish;
                                }

                                /* We always assign the same UID and GID ranges */
                                xsprintf(uid_map, "/proc/" PID_FMT "/gid_map", pid);
                                r = write_string_file(uid_map, line);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to write GID map: %m");
                                        goto finish;
                                }

                                (void) barrier_place(&barrier); /* #4 */
                        }

                        /* Block SIGCHLD here, before notifying child.
                         * process_pty() will handle it with the other signals. */
                        r = sigprocmask(SIG_BLOCK, &mask_chld, NULL);
                        if (r < 0)
                                goto finish;

                        /* Reset signal to default */
                        r = default_signals(SIGCHLD, -1);
                        if (r < 0)
                                goto finish;

                        /* Let the child know that we are ready and wait that the child is completely ready now. */
                        if (barrier_place_and_sync(&barrier)) { /* #5 */
                                _cleanup_event_unref_ sd_event *event = NULL;
                                _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
                                _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
                                char last_char = 0;

                                sd_notifyf(false,
                                           "READY=1\n"
                                           "STATUS=Container running.\n"
                                           "X_NSPAWN_LEADER_PID=" PID_FMT, pid);

                                r = sd_event_new(&event);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to get default event source: %m");
                                        goto finish;
                                }

                                if (arg_kill_signal > 0) {
                                        /* Try to kill the init system on SIGINT or SIGTERM */
                                        sd_event_add_signal(event, NULL, SIGINT, on_orderly_shutdown, UINT32_TO_PTR(pid));
                                        sd_event_add_signal(event, NULL, SIGTERM, on_orderly_shutdown, UINT32_TO_PTR(pid));
                                } else {
                                        /* Immediately exit */
                                        sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
                                        sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
                                }

                                /* simply exit on sigchld */
                                sd_event_add_signal(event, NULL, SIGCHLD, NULL, NULL);

                                if (arg_expose_ports) {
                                        r = watch_rtnl(event, rtnl_socket_pair[0], &exposed, &rtnl);
                                        if (r < 0)
                                                goto finish;

                                        (void) expose_ports(rtnl, &exposed);
                                }

                                rtnl_socket_pair[0] = safe_close(rtnl_socket_pair[0]);

                                r = pty_forward_new(event, master, true, !interactive, &forward);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to create PTY forwarder: %m");
                                        goto finish;
                                }

                                r = sd_event_loop(event);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to run event loop: %m");
                                        goto finish;
                                }

                                pty_forward_get_last_char(forward, &last_char);

                                forward = pty_forward_free(forward);

                                if (!arg_quiet && last_char != '\n')
                                        putc('\n', stdout);

                                /* Kill if it is not dead yet anyway */
                                terminate_machine(pid);
                        }
                }

                /* Normally redundant, but better safe than sorry */
                kill(pid, SIGKILL);

                r = wait_for_container(pid, &container_status);
                pid = 0;

                if (r < 0)
                        /* We failed to wait for the container, or the
                         * container exited abnormally */
                        goto finish;
                else if (r > 0 || container_status == CONTAINER_TERMINATED){
                        /* The container exited with a non-zero
                         * status, or with zero status and no reboot
                         * was requested. */
                        ret = r;
                        break;
                }

                /* CONTAINER_REBOOTED, loop again */

                if (arg_keep_unit) {
                        /* Special handling if we are running as a
                         * service: instead of simply restarting the
                         * machine we want to restart the entire
                         * service, so let's inform systemd about this
                         * with the special exit code 133. The service
                         * file uses RestartForceExitStatus=133 so
                         * that this results in a full nspawn
                         * restart. This is necessary since we might
                         * have cgroup parameters set we want to have
                         * flushed out. */
                        ret = 133;
                        r = 0;
                        break;
                }

                flush_ports(&exposed);
        }

finish:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Terminating...");

        loop_remove(loop_nr, &image_fd);

        if (pid > 0)
                kill(pid, SIGKILL);

        if (remove_subvol && arg_directory) {
                int k;

                k = btrfs_subvol_remove(arg_directory, true);
                if (k < 0)
                        log_warning_errno(k, "Cannot remove subvolume '%s', ignoring: %m", arg_directory);
        }

        if (arg_machine) {
                const char *p;

                p = strjoina("/run/systemd/nspawn/propagate/", arg_machine);
                (void) rm_rf(p, REMOVE_ROOT);
        }

        free(arg_directory);
        free(arg_template);
        free(arg_image);
        free(arg_machine);
        free(arg_user);
        strv_free(arg_setenv);
        strv_free(arg_network_interfaces);
        strv_free(arg_network_macvlan);
        strv_free(arg_network_ipvlan);
        strv_free(arg_bind);
        strv_free(arg_bind_ro);
        strv_free(arg_tmpfs);

        flush_ports(&exposed);

        while (arg_expose_ports) {
                ExposePort *p = arg_expose_ports;
                LIST_REMOVE(ports, arg_expose_ports, p);
                free(p);
        }

        return r < 0 ? EXIT_FAILURE : ret;
}
