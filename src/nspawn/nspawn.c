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

#ifdef HAVE_BLKID
#include <blkid/blkid.h>
#endif
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <linux/loop.h>
#include <pwd.h>
#include <sched.h>
#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "barrier.h"
#include "base-filesystem.h"
#include "blkid-util.h"
#include "btrfs-util.h"
#include "cap-list.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "copy.h"
#include "dev-setup.h"
#include "env-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "formats-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "hostname-util.h"
#include "log.h"
#include "loopback-setup.h"
#include "machine-id-setup.h"
#include "machine-image.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "mount-util.h"
#include "netlink-util.h"
#include "nspawn-cgroup.h"
#include "nspawn-expose-ports.h"
#include "nspawn-mount.h"
#include "nspawn-network.h"
#include "nspawn-patch-uid.h"
#include "nspawn-register.h"
#include "nspawn-settings.h"
#include "nspawn-setuid.h"
#include "nspawn-stub-pid1.h"
#include "nspawn-seccomp.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "random-util.h"
#include "raw-clone.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "udev-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "util.h"

/* Note that devpts's gid= parameter parses GIDs as signed values, hence we stay away from the upper half of the 32bit
 * UID range here */
#define UID_SHIFT_PICK_MIN ((uid_t) UINT32_C(0x00080000))
#define UID_SHIFT_PICK_MAX ((uid_t) UINT32_C(0x6FFF0000))
/* nspawn is listening on the socket at the path in the constant nspawn_notify_socket_path
 * nspawn_notify_socket_path is relative to the container
 * the init process in the container pid can send messages to nspawn following the sd_notify(3) protocol */
#define NSPAWN_NOTIFY_SOCKET_PATH "/run/systemd/nspawn/notify"

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

static char *arg_directory = NULL;
static char *arg_template = NULL;
static char *arg_chdir = NULL;
static char *arg_user = NULL;
static sd_id128_t arg_uuid = {};
static char *arg_machine = NULL;
static const char *arg_selinux_context = NULL;
static const char *arg_selinux_apifs_context = NULL;
static const char *arg_slice = NULL;
static bool arg_private_network = false;
static bool arg_read_only = false;
static StartMode arg_start_mode = START_PID1;
static bool arg_ephemeral = false;
static LinkJournal arg_link_journal = LINK_AUTO;
static bool arg_link_journal_try = false;
static uint64_t arg_caps_retain =
        (1ULL << CAP_AUDIT_CONTROL) |
        (1ULL << CAP_AUDIT_WRITE) |
        (1ULL << CAP_CHOWN) |
        (1ULL << CAP_DAC_OVERRIDE) |
        (1ULL << CAP_DAC_READ_SEARCH) |
        (1ULL << CAP_FOWNER) |
        (1ULL << CAP_FSETID) |
        (1ULL << CAP_IPC_OWNER) |
        (1ULL << CAP_KILL) |
        (1ULL << CAP_LEASE) |
        (1ULL << CAP_LINUX_IMMUTABLE) |
        (1ULL << CAP_MKNOD) |
        (1ULL << CAP_NET_BIND_SERVICE) |
        (1ULL << CAP_NET_BROADCAST) |
        (1ULL << CAP_NET_RAW) |
        (1ULL << CAP_SETFCAP) |
        (1ULL << CAP_SETGID) |
        (1ULL << CAP_SETPCAP) |
        (1ULL << CAP_SETUID) |
        (1ULL << CAP_SYS_ADMIN) |
        (1ULL << CAP_SYS_BOOT) |
        (1ULL << CAP_SYS_CHROOT) |
        (1ULL << CAP_SYS_NICE) |
        (1ULL << CAP_SYS_PTRACE) |
        (1ULL << CAP_SYS_RESOURCE) |
        (1ULL << CAP_SYS_TTY_CONFIG);
static CustomMount *arg_custom_mounts = NULL;
static unsigned arg_n_custom_mounts = 0;
static char **arg_setenv = NULL;
static bool arg_quiet = false;
static bool arg_share_system = false;
static bool arg_register = true;
static bool arg_keep_unit = false;
static char **arg_network_interfaces = NULL;
static char **arg_network_macvlan = NULL;
static char **arg_network_ipvlan = NULL;
static bool arg_network_veth = false;
static char **arg_network_veth_extra = NULL;
static char *arg_network_bridge = NULL;
static char *arg_network_zone = NULL;
static unsigned long arg_personality = PERSONALITY_INVALID;
static char *arg_image = NULL;
static VolatileMode arg_volatile_mode = VOLATILE_NO;
static ExposePort *arg_expose_ports = NULL;
static char **arg_property = NULL;
static UserNamespaceMode arg_userns_mode = USER_NAMESPACE_NO;
static uid_t arg_uid_shift = UID_INVALID, arg_uid_range = 0x10000U;
static bool arg_userns_chown = false;
static int arg_kill_signal = 0;
static bool arg_unified_cgroup_hierarchy = false;
static SettingsMask arg_settings_mask = 0;
static int arg_settings_trusted = -1;
static char **arg_parameters = NULL;
static const char *arg_container_service_name = "systemd-nspawn";
static bool arg_notify_ready = false;

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
               "  -a --as-pid2              Maintain a stub init as PID1, invoke binary as PID2\n"
               "  -b --boot                 Boot up full system (i.e. invoke init)\n"
               "     --chdir=PATH           Set working directory in the container\n"
               "  -u --user=USER            Run the command under specified user or uid\n"
               "  -M --machine=NAME         Set the machine name for the container\n"
               "     --uuid=UUID            Set a specific machine UUID for the container\n"
               "  -S --slice=SLICE          Place the container in the specified slice\n"
               "     --property=NAME=VALUE  Set scope unit property\n"
               "  -U --private-users=pick   Run within user namespace, pick UID/GID range automatically\n"
               "     --private-users[=UIDBASE[:NUIDS]]\n"
               "                            Run within user namespace, user configured UID/GID range\n"
               "     --private-user-chown   Adjust OS tree file ownership for private UID/GID range\n"
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
               "  -n --network-veth         Add a virtual Ethernet connection between host\n"
               "                            and container\n"
               "     --network-veth-extra=HOSTIF[:CONTAINERIF]\n"
               "                            Add an additional virtual Ethernet link between\n"
               "                            host and container\n"
               "     --network-bridge=INTERFACE\n"
               "                            Add a virtual Ethernet connection between host\n"
               "                            and container and add it to an existing bridge on\n"
               "                            the host\n"
               "     --network-zone=NAME    Add a virtual Ethernet connection to the container,\n"
               "                            and add it to an automatically managed bridge interface\n"
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
               "     --link-journal=MODE    Link up guest journal, one of no, auto, guest, \n"
               "                            host, try-guest, try-host\n"
               "  -j                        Equivalent to --link-journal=try-guest\n"
               "     --read-only            Mount the root directory read-only\n"
               "     --bind=PATH[:PATH[:OPTIONS]]\n"
               "                            Bind mount a file or directory from the host into\n"
               "                            the container\n"
               "     --bind-ro=PATH[:PATH[:OPTIONS]\n"
               "                            Similar, but creates a read-only bind mount\n"
               "     --tmpfs=PATH:[OPTIONS] Mount an empty tmpfs to the specified directory\n"
               "     --overlay=PATH[:PATH...]:PATH\n"
               "                            Create an overlay mount from the host to \n"
               "                            the container\n"
               "     --overlay-ro=PATH[:PATH...]:PATH\n"
               "                            Similar, but creates a read-only overlay mount\n"
               "  -E --setenv=NAME=VALUE    Pass an environment variable to PID 1\n"
               "     --share-system         Share system namespaces with host\n"
               "     --register=BOOLEAN     Register container as machine\n"
               "     --keep-unit            Do not register a scope for the machine, reuse\n"
               "                            the service unit nspawn is running in\n"
               "     --volatile[=MODE]      Run the system in volatile mode\n"
               "     --settings=BOOLEAN     Load additional settings from .nspawn file\n"
               "     --notify-ready=BOOLEAN Receive notifications from the container's init process,\n"
               "                            accepted values: yes and no\n"
               , program_invocation_short_name);
}


static int custom_mounts_prepare(void) {
        unsigned i;
        int r;

        /* Ensure the mounts are applied prefix first. */
        qsort_safe(arg_custom_mounts, arg_n_custom_mounts, sizeof(CustomMount), custom_mount_compare);

        /* Allocate working directories for the overlay file systems that need it */
        for (i = 0; i < arg_n_custom_mounts; i++) {
                CustomMount *m = &arg_custom_mounts[i];

                if (path_equal(m->destination, "/") && arg_userns_mode != USER_NAMESPACE_NO) {

                        if (arg_userns_chown) {
                                log_error("--private-users-chown may not be combined with custom root mounts.");
                                return -EINVAL;
                        } else if (arg_uid_shift == UID_INVALID) {
                                log_error("--private-users with automatic UID shift may not be combined with custom root mounts.");
                                return -EINVAL;
                        }
                }

                if (m->type != CUSTOM_MOUNT_OVERLAY)
                        continue;

                if (m->work_dir)
                        continue;

                if (m->read_only)
                        continue;

                r = tempfn_random(m->source, NULL, &m->work_dir);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate work directory from %s: %m", m->source);
        }

        return 0;
}

static int detect_unified_cgroup_hierarchy(void) {
        const char *e;
        int r;

        /* Allow the user to control whether the unified hierarchy is used */
        e = getenv("UNIFIED_CGROUP_HIERARCHY");
        if (e) {
                r = parse_boolean(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $UNIFIED_CGROUP_HIERARCHY.");

                arg_unified_cgroup_hierarchy = r;
                return 0;
        }

        /* Otherwise inherit the default from the host system */
        r = cg_unified();
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether the unified cgroups hierarchy is used: %m");

        arg_unified_cgroup_hierarchy = r;
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
                ARG_OVERLAY,
                ARG_OVERLAY_RO,
                ARG_SHARE_SYSTEM,
                ARG_REGISTER,
                ARG_KEEP_UNIT,
                ARG_NETWORK_INTERFACE,
                ARG_NETWORK_MACVLAN,
                ARG_NETWORK_IPVLAN,
                ARG_NETWORK_BRIDGE,
                ARG_NETWORK_ZONE,
                ARG_NETWORK_VETH_EXTRA,
                ARG_PERSONALITY,
                ARG_VOLATILE,
                ARG_TEMPLATE,
                ARG_PROPERTY,
                ARG_PRIVATE_USERS,
                ARG_KILL_SIGNAL,
                ARG_SETTINGS,
                ARG_CHDIR,
                ARG_PRIVATE_USERS_CHOWN,
                ARG_NOTIFY_READY,
        };

        static const struct option options[] = {
                { "help",                  no_argument,       NULL, 'h'                   },
                { "version",               no_argument,       NULL, ARG_VERSION           },
                { "directory",             required_argument, NULL, 'D'                   },
                { "template",              required_argument, NULL, ARG_TEMPLATE          },
                { "ephemeral",             no_argument,       NULL, 'x'                   },
                { "user",                  required_argument, NULL, 'u'                   },
                { "private-network",       no_argument,       NULL, ARG_PRIVATE_NETWORK   },
                { "as-pid2",               no_argument,       NULL, 'a'                   },
                { "boot",                  no_argument,       NULL, 'b'                   },
                { "uuid",                  required_argument, NULL, ARG_UUID              },
                { "read-only",             no_argument,       NULL, ARG_READ_ONLY         },
                { "capability",            required_argument, NULL, ARG_CAPABILITY        },
                { "drop-capability",       required_argument, NULL, ARG_DROP_CAPABILITY   },
                { "link-journal",          required_argument, NULL, ARG_LINK_JOURNAL      },
                { "bind",                  required_argument, NULL, ARG_BIND              },
                { "bind-ro",               required_argument, NULL, ARG_BIND_RO           },
                { "tmpfs",                 required_argument, NULL, ARG_TMPFS             },
                { "overlay",               required_argument, NULL, ARG_OVERLAY           },
                { "overlay-ro",            required_argument, NULL, ARG_OVERLAY_RO        },
                { "machine",               required_argument, NULL, 'M'                   },
                { "slice",                 required_argument, NULL, 'S'                   },
                { "setenv",                required_argument, NULL, 'E'                   },
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
                { "network-veth-extra",    required_argument, NULL, ARG_NETWORK_VETH_EXTRA},
                { "network-bridge",        required_argument, NULL, ARG_NETWORK_BRIDGE    },
                { "network-zone",          required_argument, NULL, ARG_NETWORK_ZONE      },
                { "personality",           required_argument, NULL, ARG_PERSONALITY       },
                { "image",                 required_argument, NULL, 'i'                   },
                { "volatile",              optional_argument, NULL, ARG_VOLATILE          },
                { "port",                  required_argument, NULL, 'p'                   },
                { "property",              required_argument, NULL, ARG_PROPERTY          },
                { "private-users",         optional_argument, NULL, ARG_PRIVATE_USERS     },
                { "private-users-chown",   optional_argument, NULL, ARG_PRIVATE_USERS_CHOWN},
                { "kill-signal",           required_argument, NULL, ARG_KILL_SIGNAL       },
                { "settings",              required_argument, NULL, ARG_SETTINGS          },
                { "chdir",                 required_argument, NULL, ARG_CHDIR             },
                { "notify-ready",          required_argument, NULL, ARG_NOTIFY_READY      },
                {}
        };

        int c, r;
        const char *p, *e;
        uint64_t plus = 0, minus = 0;
        bool mask_all_settings = false, mask_no_settings = false;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hD:u:abL:M:jS:Z:qi:xp:nU", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case 'D':
                        r = parse_path_argument_and_warn(optarg, false, &arg_directory);
                        if (r < 0)
                                return r;
                        break;

                case ARG_TEMPLATE:
                        r = parse_path_argument_and_warn(optarg, false, &arg_template);
                        if (r < 0)
                                return r;
                        break;

                case 'i':
                        r = parse_path_argument_and_warn(optarg, false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case 'x':
                        arg_ephemeral = true;
                        break;

                case 'u':
                        r = free_and_strdup(&arg_user, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_settings_mask |= SETTING_USER;
                        break;

                case ARG_NETWORK_ZONE: {
                        char *j;

                        j = strappend("vz-", optarg);
                        if (!j)
                                return log_oom();

                        if (!ifname_valid(j)) {
                                log_error("Network zone name not valid: %s", j);
                                free(j);
                                return -EINVAL;
                        }

                        free(arg_network_zone);
                        arg_network_zone = j;

                        arg_network_veth = true;
                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;
                }

                case ARG_NETWORK_BRIDGE:

                        if (!ifname_valid(optarg)) {
                                log_error("Bridge interface name not valid: %s", optarg);
                                return -EINVAL;
                        }

                        r = free_and_strdup(&arg_network_bridge, optarg);
                        if (r < 0)
                                return log_oom();

                        /* fall through */

                case 'n':
                        arg_network_veth = true;
                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_VETH_EXTRA:
                        r = veth_extra_parse(&arg_network_veth_extra, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --network-veth-extra= parameter: %s", optarg);

                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_INTERFACE:

                        if (!ifname_valid(optarg)) {
                                log_error("Network interface name not valid: %s", optarg);
                                return -EINVAL;
                        }

                        if (strv_extend(&arg_network_interfaces, optarg) < 0)
                                return log_oom();

                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_MACVLAN:

                        if (!ifname_valid(optarg)) {
                                log_error("MACVLAN network interface name not valid: %s", optarg);
                                return -EINVAL;
                        }

                        if (strv_extend(&arg_network_macvlan, optarg) < 0)
                                return log_oom();

                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_IPVLAN:

                        if (!ifname_valid(optarg)) {
                                log_error("IPVLAN network interface name not valid: %s", optarg);
                                return -EINVAL;
                        }

                        if (strv_extend(&arg_network_ipvlan, optarg) < 0)
                                return log_oom();

                        /* fall through */

                case ARG_PRIVATE_NETWORK:
                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case 'b':
                        if (arg_start_mode == START_PID2) {
                                log_error("--boot and --as-pid2 may not be combined.");
                                return -EINVAL;
                        }

                        arg_start_mode = START_BOOT;
                        arg_settings_mask |= SETTING_START_MODE;
                        break;

                case 'a':
                        if (arg_start_mode == START_BOOT) {
                                log_error("--boot and --as-pid2 may not be combined.");
                                return -EINVAL;
                        }

                        arg_start_mode = START_PID2;
                        arg_settings_mask |= SETTING_START_MODE;
                        break;

                case ARG_UUID:
                        r = sd_id128_from_string(optarg, &arg_uuid);
                        if (r < 0) {
                                log_error("Invalid UUID: %s", optarg);
                                return r;
                        }

                        arg_settings_mask |= SETTING_MACHINE_ID;
                        break;

                case 'S':
                        arg_slice = optarg;
                        break;

                case 'M':
                        if (isempty(optarg))
                                arg_machine = mfree(arg_machine);
                        else {
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
                        arg_settings_mask |= SETTING_READ_ONLY;
                        break;

                case ARG_CAPABILITY:
                case ARG_DROP_CAPABILITY: {
                        p = optarg;
                        for (;;) {
                                _cleanup_free_ char *t = NULL;

                                r = extract_first_word(&p, &t, ",", 0);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse capability %s.", t);

                                if (r == 0)
                                        break;

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

                        arg_settings_mask |= SETTING_CAPABILITY;
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
                case ARG_BIND_RO:
                        r = bind_mount_parse(&arg_custom_mounts, &arg_n_custom_mounts, optarg, c == ARG_BIND_RO);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --bind(-ro)= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_CUSTOM_MOUNTS;
                        break;

                case ARG_TMPFS:
                        r = tmpfs_mount_parse(&arg_custom_mounts, &arg_n_custom_mounts, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --tmpfs= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_CUSTOM_MOUNTS;
                        break;

                case ARG_OVERLAY:
                case ARG_OVERLAY_RO: {
                        _cleanup_free_ char *upper = NULL, *destination = NULL;
                        _cleanup_strv_free_ char **lower = NULL;
                        CustomMount *m;
                        unsigned n = 0;
                        char **i;

                        r = strv_split_extract(&lower, optarg, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                        if (r == -ENOMEM)
                                return log_oom();
                        else if (r < 0) {
                                log_error("Invalid overlay specification: %s", optarg);
                                return r;
                        }

                        STRV_FOREACH(i, lower) {
                                if (!path_is_absolute(*i)) {
                                        log_error("Overlay path %s is not absolute.", *i);
                                        return -EINVAL;
                                }

                                n++;
                        }

                        if (n < 2) {
                                log_error("--overlay= needs at least two colon-separated directories specified.");
                                return -EINVAL;
                        }

                        if (n == 2) {
                                /* If two parameters are specified,
                                 * the first one is the lower, the
                                 * second one the upper directory. And
                                 * we'll also define the destination
                                 * mount point the same as the upper. */
                                upper = lower[1];
                                lower[1] = NULL;

                                destination = strdup(upper);
                                if (!destination)
                                        return log_oom();

                        } else {
                                upper = lower[n - 2];
                                destination = lower[n - 1];
                                lower[n - 2] = NULL;
                        }

                        m = custom_mount_add(&arg_custom_mounts, &arg_n_custom_mounts, CUSTOM_MOUNT_OVERLAY);
                        if (!m)
                                return log_oom();

                        m->destination = destination;
                        m->source = upper;
                        m->lower = lower;
                        m->read_only = c == ARG_OVERLAY_RO;

                        upper = destination = NULL;
                        lower = NULL;

                        arg_settings_mask |= SETTING_CUSTOM_MOUNTS;
                        break;
                }

                case 'E': {
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

                        arg_settings_mask |= SETTING_ENVIRONMENT;
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
                        if (arg_personality == PERSONALITY_INVALID) {
                                log_error("Unknown or unsupported personality '%s'.", optarg);
                                return -EINVAL;
                        }

                        arg_settings_mask |= SETTING_PERSONALITY;
                        break;

                case ARG_VOLATILE:

                        if (!optarg)
                                arg_volatile_mode = VOLATILE_YES;
                        else {
                                VolatileMode m;

                                m = volatile_mode_from_string(optarg);
                                if (m < 0) {
                                        log_error("Failed to parse --volatile= argument: %s", optarg);
                                        return -EINVAL;
                                } else
                                        arg_volatile_mode = m;
                        }

                        arg_settings_mask |= SETTING_VOLATILE_MODE;
                        break;

                case 'p':
                        r = expose_port_parse(&arg_expose_ports, optarg);
                        if (r == -EEXIST)
                                return log_error_errno(r, "Duplicate port specification: %s", optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse host port %s: %m", optarg);

                        arg_settings_mask |= SETTING_EXPOSE_PORTS;
                        break;

                case ARG_PROPERTY:
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_PRIVATE_USERS:

                        r = optarg ? parse_boolean(optarg) : 1;
                        if (r == 0) {
                                /* no: User namespacing off */
                                arg_userns_mode = USER_NAMESPACE_NO;
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);
                        } else if (r > 0) {
                                /* yes: User namespacing on, UID range is read from root dir */
                                arg_userns_mode = USER_NAMESPACE_FIXED;
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);
                        } else if (streq(optarg, "pick")) {
                                /* pick: User namespacing on, UID range is picked randomly */
                                arg_userns_mode = USER_NAMESPACE_PICK;
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);
                        } else {
                                _cleanup_free_ char *buffer = NULL;
                                const char *range, *shift;

                                /* anything else: User namespacing on, UID range is explicitly configured */

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

                                arg_userns_mode = USER_NAMESPACE_FIXED;
                        }

                        arg_settings_mask |= SETTING_USERNS;
                        break;

                case 'U':
                        if (userns_supported()) {
                                arg_userns_mode = USER_NAMESPACE_PICK;
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);

                                arg_settings_mask |= SETTING_USERNS;
                        }

                        break;

                case ARG_PRIVATE_USERS_CHOWN:
                        arg_userns_chown = true;

                        arg_settings_mask |= SETTING_USERNS;
                        break;

                case ARG_KILL_SIGNAL:
                        arg_kill_signal = signal_from_string_try_harder(optarg);
                        if (arg_kill_signal < 0) {
                                log_error("Cannot parse signal: %s", optarg);
                                return -EINVAL;
                        }

                        arg_settings_mask |= SETTING_KILL_SIGNAL;
                        break;

                case ARG_SETTINGS:

                        /* no               → do not read files
                         * yes              → read files, do not override cmdline, trust only subset
                         * override         → read files, override cmdline, trust only subset
                         * trusted          → read files, do not override cmdline, trust all
                         */

                        r = parse_boolean(optarg);
                        if (r < 0) {
                                if (streq(optarg, "trusted")) {
                                        mask_all_settings = false;
                                        mask_no_settings = false;
                                        arg_settings_trusted = true;

                                } else if (streq(optarg, "override")) {
                                        mask_all_settings = false;
                                        mask_no_settings = true;
                                        arg_settings_trusted = -1;
                                } else
                                        return log_error_errno(r, "Failed to parse --settings= argument: %s", optarg);
                        } else if (r > 0) {
                                /* yes */
                                mask_all_settings = false;
                                mask_no_settings = false;
                                arg_settings_trusted = -1;
                        } else {
                                /* no */
                                mask_all_settings = true;
                                mask_no_settings = false;
                                arg_settings_trusted = false;
                        }

                        break;

                case ARG_CHDIR:
                        if (!path_is_absolute(optarg)) {
                                log_error("Working directory %s is not an absolute path.", optarg);
                                return -EINVAL;
                        }

                        r = free_and_strdup(&arg_chdir, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_settings_mask |= SETTING_WORKING_DIRECTORY;
                        break;

                case ARG_NOTIFY_READY:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("%s is not a valid notify mode. Valid modes are: yes, no, and ready.", optarg);
                                return -EINVAL;
                        }
                        arg_notify_ready = r;
                        arg_settings_mask |= SETTING_NOTIFY_READY;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_share_system)
                arg_register = false;

        if (arg_userns_mode == USER_NAMESPACE_PICK)
                arg_userns_chown = true;

        if (arg_start_mode != START_PID1 && arg_share_system) {
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

        if (arg_userns_mode != USER_NAMESPACE_NO && !userns_supported()) {
                log_error("--private-users= is not supported, kernel compiled without user namespace support.");
                return -EOPNOTSUPP;
        }

        if (arg_userns_chown && arg_read_only) {
                log_error("--read-only and --private-users-chown may not be combined.");
                return -EINVAL;
        }

        if (arg_network_bridge && arg_network_zone) {
                log_error("--network-bridge= and --network-zone= may not be combined.");
                return -EINVAL;
        }

        if (argc > optind) {
                arg_parameters = strv_copy(argv + optind);
                if (!arg_parameters)
                        return log_oom();

                arg_settings_mask |= SETTING_START_MODE;
        }

        /* Load all settings from .nspawn files */
        if (mask_no_settings)
                arg_settings_mask = 0;

        /* Don't load any settings from .nspawn files */
        if (mask_all_settings)
                arg_settings_mask = _SETTINGS_MASK_ALL;

        arg_caps_retain = (arg_caps_retain | plus | (arg_private_network ? 1ULL << CAP_NET_ADMIN : 0)) & ~minus;

        r = detect_unified_cgroup_hierarchy();
        if (r < 0)
                return r;

        e = getenv("SYSTEMD_NSPAWN_CONTAINER_SERVICE");
        if (e)
                arg_container_service_name = e;

        return 1;
}

static int verify_arguments(void) {

        if (arg_volatile_mode != VOLATILE_NO && arg_read_only) {
                log_error("Cannot combine --read-only with --volatile. Note that --volatile already implies a read-only base hierarchy.");
                return -EINVAL;
        }

        if (arg_expose_ports && !arg_private_network) {
                log_error("Cannot use --port= without private networking.");
                return -EINVAL;
        }

#ifndef HAVE_LIBIPTC
        if (arg_expose_ports) {
                log_error("--port= is not supported, compiled without libiptc support.");
                return -EOPNOTSUPP;
        }
#endif

        if (arg_start_mode == START_BOOT && arg_kill_signal <= 0)
                arg_kill_signal = SIGRTMIN+3;

        return 0;
}

static int userns_lchown(const char *p, uid_t uid, gid_t gid) {
        assert(p);

        if (arg_userns_mode == USER_NAMESPACE_NO)
                return 0;

        if (uid == UID_INVALID && gid == GID_INVALID)
                return 0;

        if (uid != UID_INVALID) {
                uid += arg_uid_shift;

                if (uid < arg_uid_shift || uid >= arg_uid_shift + arg_uid_range)
                        return -EOVERFLOW;
        }

        if (gid != GID_INVALID) {
                gid += (gid_t) arg_uid_shift;

                if (gid < (gid_t) arg_uid_shift || gid >= (gid_t) (arg_uid_shift + arg_uid_range))
                        return -EOVERFLOW;
        }

        if (lchown(p, uid, gid) < 0)
                return -errno;

        return 0;
}

static int userns_mkdir(const char *root, const char *path, mode_t mode, uid_t uid, gid_t gid) {
        const char *q;

        q = prefix_roota(root, path);
        if (mkdir(q, mode) < 0) {
                if (errno == EEXIST)
                        return 0;
                return -errno;
        }

        return userns_lchown(q, uid, gid);
}

static int setup_timezone(const char *dest) {
        _cleanup_free_ char *p = NULL, *q = NULL;
        const char *where, *check, *what;
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

        where = prefix_roota(dest, "/etc/localtime");
        r = readlink_malloc(where, &q);
        if (r >= 0) {
                y = path_startswith(q, "../usr/share/zoneinfo/");
                if (!y)
                        y = path_startswith(q, "/usr/share/zoneinfo/");

                /* Already pointing to the right place? Then do nothing .. */
                if (y && streq(y, z))
                        return 0;
        }

        check = strjoina("/usr/share/zoneinfo/", z);
        check = prefix_roota(dest, check);
        if (laccess(check, F_OK) < 0) {
                log_warning("Timezone %s does not exist in container, not updating container timezone.", z);
                return 0;
        }

        r = unlink(where);
        if (r < 0 && errno != ENOENT) {
                log_error_errno(errno, "Failed to remove existing timezone info %s in container: %m", where);
                return 0;
        }

        what = strjoina("../usr/share/zoneinfo/", z);
        if (symlink(what, where) < 0) {
                log_error_errno(errno, "Failed to correct timezone of container: %m");
                return 0;
        }

        r = userns_lchown(where, 0, 0);
        if (r < 0)
                return log_warning_errno(r, "Failed to chown /etc/localtime: %m");

        return 0;
}

static int setup_resolv_conf(const char *dest) {
        const char *where = NULL;
        int r;

        assert(dest);

        if (arg_private_network)
                return 0;

        /* Fix resolv.conf, if possible */
        where = prefix_roota(dest, "/etc/resolv.conf");

        r = copy_file("/etc/resolv.conf", where, O_TRUNC|O_NOFOLLOW, 0644, 0);
        if (r < 0) {
                /* If the file already exists as symlink, let's
                 * suppress the warning, under the assumption that
                 * resolved or something similar runs inside and the
                 * symlink points there.
                 *
                 * If the disk image is read-only, there's also no
                 * point in complaining.
                 */
                log_full_errno(IN_SET(r, -ELOOP, -EROFS) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to copy /etc/resolv.conf to %s: %m", where);
                return 0;
        }

        r = userns_lchown(where, 0, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to chown /etc/resolv.conf: %m");

        return 0;
}

static char* id128_format_as_uuid(sd_id128_t id, char s[37]) {
        assert(s);

        snprintf(s, 37,
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 SD_ID128_FORMAT_VAL(id));

        return s;
}

static int setup_boot_id(const char *dest) {
        const char *from, *to;
        sd_id128_t rnd = {};
        char as_uuid[37];
        int r;

        if (arg_share_system)
                return 0;

        /* Generate a new randomized boot ID, so that each boot-up of
         * the container gets a new one */

        from = prefix_roota(dest, "/run/proc-sys-kernel-random-boot-id");
        to = prefix_roota(dest, "/proc/sys/kernel/random/boot_id");

        r = sd_id128_randomize(&rnd);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random boot id: %m");

        id128_format_as_uuid(rnd, as_uuid);

        r = write_string_file(from, as_uuid, WRITE_STRING_FILE_CREATE);
        if (r < 0)
                return log_error_errno(r, "Failed to write boot id: %m");

        if (mount(from, to, NULL, MS_BIND, NULL) < 0)
                r = log_error_errno(errno, "Failed to bind mount boot id: %m");
        else if (mount(NULL, to, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV, NULL) < 0)
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

        /* Create /dev/net, so that we can create /dev/net/tun in it */
        if (userns_mkdir(dest, "/dev/net", 0755, 0, 0) < 0)
                return log_error_errno(r, "Failed to create /dev/net directory: %m");

        NULSTR_FOREACH(d, devnodes) {
                _cleanup_free_ char *from = NULL, *to = NULL;
                struct stat st;

                from = strappend("/dev/", d);
                to = prefix_root(dest, from);

                if (stat(from, &st) < 0) {

                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to stat %s: %m", from);

                } else if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {

                        log_error("%s is not a char or block device, cannot copy.", from);
                        return -EIO;

                } else {
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

                        r = userns_lchown(to, 0, 0);
                        if (r < 0)
                                return log_error_errno(r, "chown() of device node %s failed: %m", to);
                }
        }

        return r;
}

static int setup_pts(const char *dest) {
        _cleanup_free_ char *options = NULL;
        const char *p;
        int r;

#ifdef HAVE_SELINUX
        if (arg_selinux_apifs_context)
                (void) asprintf(&options,
                                "newinstance,ptmxmode=0666,mode=620,gid=" GID_FMT ",context=\"%s\"",
                                arg_uid_shift + TTY_GID,
                                arg_selinux_apifs_context);
        else
#endif
                (void) asprintf(&options,
                                "newinstance,ptmxmode=0666,mode=620,gid=" GID_FMT,
                                arg_uid_shift + TTY_GID);

        if (!options)
                return log_oom();

        /* Mount /dev/pts itself */
        p = prefix_roota(dest, "/dev/pts");
        if (mkdir(p, 0755) < 0)
                return log_error_errno(errno, "Failed to create /dev/pts: %m");
        if (mount("devpts", p, "devpts", MS_NOSUID|MS_NOEXEC, options) < 0)
                return log_error_errno(errno, "Failed to mount /dev/pts: %m");
        r = userns_lchown(p, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to chown /dev/pts: %m");

        /* Create /dev/ptmx symlink */
        p = prefix_roota(dest, "/dev/ptmx");
        if (symlink("pts/ptmx", p) < 0)
                return log_error_errno(errno, "Failed to create /dev/ptmx symlink: %m");
        r = userns_lchown(p, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to chown /dev/ptmx: %m");

        /* And fix /dev/pts/ptmx ownership */
        p = prefix_roota(dest, "/dev/pts/ptmx");
        r = userns_lchown(p, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to chown /dev/pts/ptmx: %m");

        return 0;
}

static int setup_dev_console(const char *dest, const char *console) {
        _cleanup_umask_ mode_t u;
        const char *to;
        int r;

        assert(dest);
        assert(console);

        u = umask(0000);

        r = chmod_and_chown(console, 0600, arg_uid_shift, arg_uid_shift);
        if (r < 0)
                return log_error_errno(r, "Failed to correct access mode for TTY: %m");

        /* We need to bind mount the right tty to /dev/console since
         * ptys can only exist on pts file systems. To have something
         * to bind mount things on we create a empty regular file. */

        to = prefix_roota(dest, "/dev/console");
        r = touch(to);
        if (r < 0)
                return log_error_errno(r, "touch() for /dev/console failed: %m");

        if (mount(console, to, NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Bind mount for /dev/console failed: %m");

        return 0;
}

static int setup_kmsg(const char *dest, int kmsg_socket) {
        const char *from, *to;
        _cleanup_umask_ mode_t u;
        int fd, r;

        assert(kmsg_socket >= 0);

        u = umask(0000);

        /* We create the kmsg FIFO as /run/kmsg, but immediately
         * delete it after bind mounting it to /proc/kmsg. While FIFOs
         * on the reading side behave very similar to /proc/kmsg,
         * their writing side behaves differently from /dev/kmsg in
         * that writing blocks when nothing is reading. In order to
         * avoid any problems with containers deadlocking due to this
         * we simply make /dev/kmsg unavailable to the container. */
        from = prefix_roota(dest, "/run/kmsg");
        to = prefix_roota(dest, "/proc/kmsg");

        if (mkfifo(from, 0600) < 0)
                return log_error_errno(errno, "mkfifo() for /run/kmsg failed: %m");
        if (mount(from, to, NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Bind mount for /proc/kmsg failed: %m");

        fd = open(from, O_RDWR|O_NDELAY|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open fifo: %m");

        /* Store away the fd in the socket, so that it stays open as
         * long as we run the child */
        r = send_one_fd(kmsg_socket, fd, 0);
        safe_close(fd);

        if (r < 0)
                return log_error_errno(r, "Failed to send FIFO fd: %m");

        /* And now make the FIFO unavailable as /run/kmsg... */
        (void) unlink(from);

        return 0;
}

static int on_address_change(sd_netlink *rtnl, sd_netlink_message *m, void *userdata) {
        union in_addr_union *exposed = userdata;

        assert(rtnl);
        assert(m);
        assert(exposed);

        expose_port_execute(rtnl, arg_expose_ports, exposed);
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
        sd_id128_t this_id;
        _cleanup_free_ char *d = NULL;
        const char *p, *q;
        bool try;
        char id[33];
        int r;

        /* Don't link journals in ephemeral mode */
        if (arg_ephemeral)
                return 0;

        if (arg_link_journal == LINK_NO)
                return 0;

        try = arg_link_journal_try || arg_link_journal == LINK_AUTO;

        r = sd_id128_get_machine(&this_id);
        if (r < 0)
                return log_error_errno(r, "Failed to retrieve machine ID: %m");

        if (sd_id128_equal(arg_uuid, this_id)) {
                log_full(try ? LOG_WARNING : LOG_ERR,
                         "Host and machine ids are equal (%s): refusing to link journals", sd_id128_to_string(arg_uuid, id));
                if (try)
                        return 0;
                return -EEXIST;
        }

        r = userns_mkdir(directory, "/var", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /var: %m");

        r = userns_mkdir(directory, "/var/log", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /var/log: %m");

        r = userns_mkdir(directory, "/var/log/journal", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /var/log/journal: %m");

        (void) sd_id128_to_string(arg_uuid, id);

        p = strjoina("/var/log/journal/", id);
        q = prefix_roota(directory, p);

        if (path_is_mount_point(p, 0) > 0) {
                if (try)
                        return 0;

                log_error("%s: already a mount point, refusing to use for journal", p);
                return -EEXIST;
        }

        if (path_is_mount_point(q, 0) > 0) {
                if (try)
                        return 0;

                log_error("%s: already a mount point, refusing to use for journal", q);
                return -EEXIST;
        }

        r = readlink_and_make_absolute(p, &d);
        if (r >= 0) {
                if ((arg_link_journal == LINK_GUEST ||
                     arg_link_journal == LINK_AUTO) &&
                    path_equal(d, q)) {

                        r = userns_mkdir(directory, p, 0755, 0, 0);
                        if (r < 0)
                                log_warning_errno(r, "Failed to create directory %s: %m", q);
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
                        } else
                                return log_error_errno(errno, "Failed to remove %s: %m", p);
                }
        } else if (r != -ENOENT)
                return log_error_errno(r, "readlink(%s) failed: %m", p);

        if (arg_link_journal == LINK_GUEST) {

                if (symlink(q, p) < 0) {
                        if (try) {
                                log_debug_errno(errno, "Failed to symlink %s to %s, skipping journal setup: %m", q, p);
                                return 0;
                        } else
                                return log_error_errno(errno, "Failed to symlink %s to %s: %m", q, p);
                }

                r = userns_mkdir(directory, p, 0755, 0, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to create directory %s: %m", q);
                return 0;
        }

        if (arg_link_journal == LINK_HOST) {
                /* don't create parents here — if the host doesn't have
                 * permanent journal set up, don't force it here */

                if (mkdir(p, 0755) < 0 && errno != EEXIST) {
                        if (try) {
                                log_debug_errno(errno, "Failed to create %s, skipping journal setup: %m", p);
                                return 0;
                        } else
                                return log_error_errno(errno, "Failed to create %s: %m", p);
                }

        } else if (access(p, F_OK) < 0)
                return 0;

        if (dir_is_empty(q) == 0)
                log_warning("%s is not empty, proceeding anyway.", q);

        r = userns_mkdir(directory, p, 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s: %m", q);

        if (mount(p, q, NULL, MS_BIND, NULL) < 0)
                return log_error_errno(errno, "Failed to bind mount journal from host into guest: %m");

        return 0;
}

static int drop_capabilities(void) {
        return capability_bounding_set_drop(arg_caps_retain, false);
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

        r = write_string_file("/proc/self/loginuid", "4294967295", 0);
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


static int setup_propagate(const char *root) {
        const char *p, *q;
        int r;

        (void) mkdir_p("/run/systemd/nspawn/", 0755);
        (void) mkdir_p("/run/systemd/nspawn/propagate", 0600);
        p = strjoina("/run/systemd/nspawn/propagate/", arg_machine);
        (void) mkdir_p(p, 0600);

        r = userns_mkdir(root, "/run/systemd", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd: %m");

        r = userns_mkdir(root, "/run/systemd/nspawn", 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd/nspawn: %m");

        r = userns_mkdir(root, "/run/systemd/nspawn/incoming", 0600, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/systemd/nspawn/incoming: %m");

        q = prefix_roota(root, "/run/systemd/nspawn/incoming");
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
                log_error("%s is not a regular file or block device.", arg_image);
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

                return log_error_errno(errno, "Failed to set device on blkid probe: %m");
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
                return log_error_errno(errno, "Failed to probe: %m");
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

                        return log_error_errno(errno, "Failed to get partition device of %s: %m", arg_image);
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
                return log_error_errno(errno, "Failed to allocate prober for %s: %m", what);
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
                return log_error_errno(errno, "Failed to probe %s: %m", what);
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

static int setup_machine_id(const char *directory) {
        int r;
        const char *etc_machine_id, *t;
        _cleanup_free_ char *s = NULL;

        etc_machine_id = prefix_roota(directory, "/etc/machine-id");

        r = read_one_line_file(etc_machine_id, &s);
        if (r < 0)
                return log_error_errno(r, "Failed to read machine ID from %s: %m", etc_machine_id);

        t = strstrip(s);

        if (!isempty(t)) {
                r = sd_id128_from_string(t, &arg_uuid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse machine ID from %s: %m", etc_machine_id);
        } else {
                if (sd_id128_is_null(arg_uuid)) {
                        r = sd_id128_randomize(&arg_uuid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to generate random machine ID: %m");
                }
        }

        r = machine_id_setup(directory, arg_uuid);
        if (r < 0)
                return log_error_errno(r, "Failed to setup machine ID: %m");

        return 0;
}

static int recursive_chown(const char *directory, uid_t shift, uid_t range) {
        int r;

        assert(directory);

        if (arg_userns_mode == USER_NAMESPACE_NO || !arg_userns_chown)
                return 0;

        r = path_patch_uid(directory, arg_uid_shift, arg_uid_range);
        if (r == -EOPNOTSUPP)
                return log_error_errno(r, "Automatic UID/GID adjusting is only supported for UID/GID ranges starting at multiples of 2^16 with a range of 2^16.");
        if (r == -EBADE)
                return log_error_errno(r, "Upper 16 bits of root directory UID and GID do not match.");
        if (r < 0)
                return log_error_errno(r, "Failed to adjust UID/GID shift of OS tree: %m");
        if (r == 0)
                log_debug("Root directory of image is already owned by the right UID/GID range, skipping recursive chown operation.");
        else
                log_debug("Patched directory tree to match UID/GID range.");

        return r;
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
                if (status.si_status == 0)
                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO, "Container %s exited successfully.", arg_machine);
                else
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
}

static int on_orderly_shutdown(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        pid_t pid;

        pid = PTR_TO_PID(userdata);
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

        if (arg_template && !arg_directory && arg_machine) {

                /* If --template= was specified then we should not
                 * search for a machine, but instead create a new one
                 * in /var/lib/machine. */

                arg_directory = strjoin("/var/lib/machines/", arg_machine, NULL);
                if (!arg_directory)
                        return log_oom();
        }

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
                                r = free_and_strdup(&arg_image, i->path);
                        else
                                r = free_and_strdup(&arg_directory, i->path);
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

                hostname_cleanup(arg_machine);
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

static int determine_uid_shift(const char *directory) {
        int r;

        if (arg_userns_mode == USER_NAMESPACE_NO) {
                arg_uid_shift = 0;
                return 0;
        }

        if (arg_uid_shift == UID_INVALID) {
                struct stat st;

                r = stat(directory, &st);
                if (r < 0)
                        return log_error_errno(errno, "Failed to determine UID base of %s: %m", directory);

                arg_uid_shift = st.st_uid & UINT32_C(0xffff0000);

                if (arg_uid_shift != (st.st_gid & UINT32_C(0xffff0000))) {
                        log_error("UID and GID base of %s don't match.", directory);
                        return -EINVAL;
                }

                arg_uid_range = UINT32_C(0x10000);
        }

        if (arg_uid_shift > (uid_t) -1 - arg_uid_range) {
                log_error("UID base too high for UID range.");
                return -EINVAL;
        }

        return 0;
}

static int inner_child(
                Barrier *barrier,
                const char *directory,
                bool secondary,
                int kmsg_socket,
                int rtnl_socket,
                FDSet *fds) {

        _cleanup_free_ char *home = NULL;
        char as_uuid[37];
        unsigned n_env = 1;
        const char *envp[] = {
                "PATH=" DEFAULT_PATH_SPLIT_USR,
                NULL, /* container */
                NULL, /* TERM */
                NULL, /* HOME */
                NULL, /* USER */
                NULL, /* LOGNAME */
                NULL, /* container_uuid */
                NULL, /* LISTEN_FDS */
                NULL, /* LISTEN_PID */
                NULL, /* NOTIFY_SOCKET */
                NULL
        };

        _cleanup_strv_free_ char **env_use = NULL;
        int r;

        assert(barrier);
        assert(directory);
        assert(kmsg_socket >= 0);

        cg_unified_flush();

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                /* Tell the parent, that it now can write the UID map. */
                (void) barrier_place(barrier); /* #1 */

                /* Wait until the parent wrote the UID map */
                if (!barrier_place_and_sync(barrier)) { /* #2 */
                        log_error("Parent died too early");
                        return -ESRCH;
                }
        }

        r = mount_all(NULL,
                      arg_userns_mode != USER_NAMESPACE_NO,
                      true,
                      arg_private_network,
                      arg_uid_shift,
                      arg_uid_range,
                      arg_selinux_apifs_context);

        if (r < 0)
                return r;

        r = mount_sysfs(NULL);
        if (r < 0)
                return r;

        /* Wait until we are cgroup-ified, so that we
         * can mount the right cgroup path writable */
        if (!barrier_place_and_sync(barrier)) { /* #3 */
                log_error("Parent died too early");
                return -ESRCH;
        }

        r = mount_systemd_cgroup_writable("", arg_unified_cgroup_hierarchy);
        if (r < 0)
                return r;

        r = reset_uid_gid();
        if (r < 0)
                return log_error_errno(r, "Couldn't become new root: %m");

        r = setup_boot_id(NULL);
        if (r < 0)
                return r;

        r = setup_kmsg(NULL, kmsg_socket);
        if (r < 0)
                return r;
        kmsg_socket = safe_close(kmsg_socket);

        umask(0022);

        if (setsid() < 0)
                return log_error_errno(errno, "setsid() failed: %m");

        if (arg_private_network)
                loopback_setup();

        if (arg_expose_ports) {
                r = expose_port_send_rtnl(rtnl_socket);
                if (r < 0)
                        return r;
                rtnl_socket = safe_close(rtnl_socket);
        }

        r = drop_capabilities();
        if (r < 0)
                return log_error_errno(r, "drop_capabilities() failed: %m");

        setup_hostname();

        if (arg_personality != PERSONALITY_INVALID) {
                if (personality(arg_personality) < 0)
                        return log_error_errno(errno, "personality() failed: %m");
        } else if (secondary) {
                if (personality(PER_LINUX32) < 0)
                        return log_error_errno(errno, "personality() failed: %m");
        }

#ifdef HAVE_SELINUX
        if (arg_selinux_context)
                if (setexeccon(arg_selinux_context) < 0)
                        return log_error_errno(errno, "setexeccon(\"%s\") failed: %m", arg_selinux_context);
#endif

        r = change_uid_gid(arg_user, &home);
        if (r < 0)
                return r;

        /* LXC sets container=lxc, so follow the scheme here */
        envp[n_env++] = strjoina("container=", arg_container_service_name);

        envp[n_env] = strv_find_prefix(environ, "TERM=");
        if (envp[n_env])
                n_env++;

        if ((asprintf((char**)(envp + n_env++), "HOME=%s", home ? home: "/root") < 0) ||
            (asprintf((char**)(envp + n_env++), "USER=%s", arg_user ? arg_user : "root") < 0) ||
            (asprintf((char**)(envp + n_env++), "LOGNAME=%s", arg_user ? arg_user : "root") < 0))
                return log_oom();

        assert(!sd_id128_equal(arg_uuid, SD_ID128_NULL));

        if (asprintf((char**)(envp + n_env++), "container_uuid=%s", id128_format_as_uuid(arg_uuid, as_uuid)) < 0)
                return log_oom();

        if (fdset_size(fds) > 0) {
                r = fdset_cloexec(fds, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to unset O_CLOEXEC for file descriptors.");

                if ((asprintf((char **)(envp + n_env++), "LISTEN_FDS=%u", fdset_size(fds)) < 0) ||
                    (asprintf((char **)(envp + n_env++), "LISTEN_PID=1") < 0))
                        return log_oom();
        }
        if (asprintf((char **)(envp + n_env++), "NOTIFY_SOCKET=%s", NSPAWN_NOTIFY_SOCKET_PATH) < 0)
                return log_oom();

        env_use = strv_env_merge(2, envp, arg_setenv);
        if (!env_use)
                return log_oom();

        /* Let the parent know that we are ready and
         * wait until the parent is ready with the
         * setup, too... */
        if (!barrier_place_and_sync(barrier)) { /* #4 */
                log_error("Parent died too early");
                return -ESRCH;
        }

        if (arg_chdir)
                if (chdir(arg_chdir) < 0)
                        return log_error_errno(errno, "Failed to change to specified working directory %s: %m", arg_chdir);

        if (arg_start_mode == START_PID2) {
                r = stub_pid1();
                if (r < 0)
                        return r;
        }

        /* Now, explicitly close the log, so that we
         * then can close all remaining fds. Closing
         * the log explicitly first has the benefit
         * that the logging subsystem knows about it,
         * and is thus ready to be reopened should we
         * need it again. Note that the other fds
         * closed here are at least the locking and
         * barrier fds. */
        log_close();
        (void) fdset_close_others(fds);

        if (arg_start_mode == START_BOOT) {
                char **a;
                size_t m;

                /* Automatically search for the init system */

                m = strv_length(arg_parameters);
                a = newa(char*, m + 2);
                memcpy_safe(a + 1, arg_parameters, m * sizeof(char*));
                a[1 + m] = NULL;

                a[0] = (char*) "/usr/lib/systemd/systemd";
                execve(a[0], a, env_use);

                a[0] = (char*) "/lib/systemd/systemd";
                execve(a[0], a, env_use);

                a[0] = (char*) "/sbin/init";
                execve(a[0], a, env_use);
        } else if (!strv_isempty(arg_parameters))
                execvpe(arg_parameters[0], arg_parameters, env_use);
        else {
                if (!arg_chdir)
                        /* If we cannot change the directory, we'll end up in /, that is expected. */
                        (void) chdir(home ?: "/root");

                execle("/bin/bash", "-bash", NULL, env_use);
                execle("/bin/sh", "-sh", NULL, env_use);
        }

        r = -errno;
        (void) log_open();
        return log_error_errno(r, "execv() failed: %m");
}

static int setup_sd_notify_child(void) {
        static const int one = 1;
        int fd = -1;
        union sockaddr_union sa = {
                .sa.sa_family = AF_UNIX,
        };
        int r;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate notification socket: %m");

        (void) mkdir_parents(NSPAWN_NOTIFY_SOCKET_PATH, 0755);
        (void) unlink(NSPAWN_NOTIFY_SOCKET_PATH);

        strncpy(sa.un.sun_path, NSPAWN_NOTIFY_SOCKET_PATH, sizeof(sa.un.sun_path)-1);
        r = bind(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
        if (r < 0) {
                safe_close(fd);
                return log_error_errno(errno, "bind(%s) failed: %m", sa.un.sun_path);
        }

        r = setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one));
        if (r < 0) {
                safe_close(fd);
                return log_error_errno(errno, "SO_PASSCRED failed: %m");
        }

        return fd;
}

static int outer_child(
                Barrier *barrier,
                const char *directory,
                const char *console,
                const char *root_device, bool root_device_rw,
                const char *home_device, bool home_device_rw,
                const char *srv_device, bool srv_device_rw,
                bool interactive,
                bool secondary,
                int pid_socket,
                int uuid_socket,
                int notify_socket,
                int kmsg_socket,
                int rtnl_socket,
                int uid_shift_socket,
                FDSet *fds) {

        pid_t pid;
        ssize_t l;
        int r;
        _cleanup_close_ int fd = -1;

        assert(barrier);
        assert(directory);
        assert(console);
        assert(pid_socket >= 0);
        assert(uuid_socket >= 0);
        assert(notify_socket >= 0);
        assert(kmsg_socket >= 0);

        cg_unified_flush();

        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
                return log_error_errno(errno, "PR_SET_PDEATHSIG failed: %m");

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

                        return log_error_errno(r, "Failed to open console: %m");
                }

                if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO ||
                    dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
                        return log_error_errno(errno, "Failed to duplicate console: %m");
        }

        r = reset_audit_loginuid();
        if (r < 0)
                return r;

        /* Mark everything as slave, so that we still
         * receive mounts from the real root, but don't
         * propagate mounts to the real root. */
        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                return log_error_errno(errno, "MS_SLAVE|MS_REC failed: %m");

        r = mount_devices(directory,
                          root_device, root_device_rw,
                          home_device, home_device_rw,
                          srv_device, srv_device_rw);
        if (r < 0)
                return r;

        r = determine_uid_shift(directory);
        if (r < 0)
                return r;

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                /* Let the parent know which UID shift we read from the image */
                l = send(uid_shift_socket, &arg_uid_shift, sizeof(arg_uid_shift), MSG_NOSIGNAL);
                if (l < 0)
                        return log_error_errno(errno, "Failed to send UID shift: %m");
                if (l != sizeof(arg_uid_shift)) {
                        log_error("Short write while sending UID shift.");
                        return -EIO;
                }

                if (arg_userns_mode == USER_NAMESPACE_PICK) {
                        /* When we are supposed to pick the UID shift, the parent will check now whether the UID shift
                         * we just read from the image is available. If yes, it will send the UID shift back to us, if
                         * not it will pick a different one, and send it back to us. */

                        l = recv(uid_shift_socket, &arg_uid_shift, sizeof(arg_uid_shift), 0);
                        if (l < 0)
                                return log_error_errno(errno, "Failed to recv UID shift: %m");
                        if (l != sizeof(arg_uid_shift)) {
                                log_error("Short read while receiving UID shift.");
                                return -EIO;
                        }
                }

                log_info("Selected user namespace base " UID_FMT " and range " UID_FMT ".", arg_uid_shift, arg_uid_range);
        }

        /* Turn directory into bind mount */
        if (mount(directory, directory, NULL, MS_BIND|MS_REC, NULL) < 0)
                return log_error_errno(errno, "Failed to make bind mount: %m");

        r = recursive_chown(directory, arg_uid_shift, arg_uid_range);
        if (r < 0)
                return r;

        r = setup_volatile(
                        directory,
                        arg_volatile_mode,
                        arg_userns_mode != USER_NAMESPACE_NO,
                        arg_uid_shift,
                        arg_uid_range,
                        arg_selinux_context);
        if (r < 0)
                return r;

        r = setup_volatile_state(
                        directory,
                        arg_volatile_mode,
                        arg_userns_mode != USER_NAMESPACE_NO,
                        arg_uid_shift,
                        arg_uid_range,
                        arg_selinux_context);
        if (r < 0)
                return r;

        r = base_filesystem_create(directory, arg_uid_shift, (gid_t) arg_uid_shift);
        if (r < 0)
                return r;

        if (arg_read_only) {
                r = bind_remount_recursive(directory, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to make tree read-only: %m");
        }

        r = mount_all(directory,
                      arg_userns_mode != USER_NAMESPACE_NO,
                      false,
                      arg_private_network,
                      arg_uid_shift,
                      arg_uid_range,
                      arg_selinux_apifs_context);
        if (r < 0)
                return r;

        r = copy_devnodes(directory);
        if (r < 0)
                return r;

        dev_setup(directory, arg_uid_shift, arg_uid_shift);

        r = setup_pts(directory);
        if (r < 0)
                return r;

        r = setup_propagate(directory);
        if (r < 0)
                return r;

        r = setup_dev_console(directory, console);
        if (r < 0)
                return r;

        r = setup_seccomp(arg_caps_retain);
        if (r < 0)
                return r;

        r = setup_timezone(directory);
        if (r < 0)
                return r;

        r = setup_resolv_conf(directory);
        if (r < 0)
                return r;

        r = setup_machine_id(directory);
        if (r < 0)
                return r;

        r = setup_journal(directory);
        if (r < 0)
                return r;

        r = mount_custom(
                        directory,
                        arg_custom_mounts,
                        arg_n_custom_mounts,
                        arg_userns_mode != USER_NAMESPACE_NO,
                        arg_uid_shift,
                        arg_uid_range,
                        arg_selinux_apifs_context);
        if (r < 0)
                return r;

        r = mount_cgroups(
                        directory,
                        arg_unified_cgroup_hierarchy,
                        arg_userns_mode != USER_NAMESPACE_NO,
                        arg_uid_shift,
                        arg_uid_range,
                        arg_selinux_apifs_context);
        if (r < 0)
                return r;

        r = mount_move_root(directory);
        if (r < 0)
                return log_error_errno(r, "Failed to move root directory: %m");

        fd = setup_sd_notify_child();
        if (fd < 0)
                return fd;

        pid = raw_clone(SIGCHLD|CLONE_NEWNS|
                        (arg_share_system ? 0 : CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS) |
                        (arg_private_network ? CLONE_NEWNET : 0) |
                        (arg_userns_mode != USER_NAMESPACE_NO ? CLONE_NEWUSER : 0));
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork inner child: %m");
        if (pid == 0) {
                pid_socket = safe_close(pid_socket);
                uuid_socket = safe_close(uuid_socket);
                notify_socket = safe_close(notify_socket);
                uid_shift_socket = safe_close(uid_shift_socket);

                /* The inner child has all namespaces that are
                 * requested, so that we all are owned by the user if
                 * user namespaces are turned on. */

                r = inner_child(barrier, directory, secondary, kmsg_socket, rtnl_socket, fds);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        l = send(pid_socket, &pid, sizeof(pid), MSG_NOSIGNAL);
        if (l < 0)
                return log_error_errno(errno, "Failed to send PID: %m");
        if (l != sizeof(pid)) {
                log_error("Short write while sending PID.");
                return -EIO;
        }

        l = send(uuid_socket, &arg_uuid, sizeof(arg_uuid), MSG_NOSIGNAL);
        if (l < 0)
                return log_error_errno(errno, "Failed to send machine ID: %m");
        if (l != sizeof(arg_uuid)) {
                log_error("Short write while sending machine ID.");
                return -EIO;
        }

        l = send_one_fd(notify_socket, fd, 0);
        if (l < 0)
                return log_error_errno(errno, "Failed to send notify fd: %m");

        pid_socket = safe_close(pid_socket);
        uuid_socket = safe_close(uuid_socket);
        notify_socket = safe_close(notify_socket);
        kmsg_socket = safe_close(kmsg_socket);
        rtnl_socket = safe_close(rtnl_socket);

        return 0;
}

static int uid_shift_pick(uid_t *shift, LockFile *ret_lock_file) {
        unsigned n_tries = 100;
        uid_t candidate;
        int r;

        assert(shift);
        assert(ret_lock_file);
        assert(arg_userns_mode == USER_NAMESPACE_PICK);
        assert(arg_uid_range == 0x10000U);

        candidate = *shift;

        (void) mkdir("/run/systemd/nspawn-uid", 0755);

        for (;;) {
                char lock_path[strlen("/run/systemd/nspawn-uid/") + DECIMAL_STR_MAX(uid_t) + 1];
                _cleanup_release_lock_file_ LockFile lf = LOCK_FILE_INIT;

                if (--n_tries <= 0)
                        return -EBUSY;

                if (candidate < UID_SHIFT_PICK_MIN || candidate > UID_SHIFT_PICK_MAX)
                        goto next;
                if ((candidate & UINT32_C(0xFFFF)) != 0)
                        goto next;

                xsprintf(lock_path, "/run/systemd/nspawn-uid/" UID_FMT, candidate);
                r = make_lock_file(lock_path, LOCK_EX|LOCK_NB, &lf);
                if (r == -EBUSY) /* Range already taken by another nspawn instance */
                        goto next;
                if (r < 0)
                        return r;

                /* Make some superficial checks whether the range is currently known in the user database */
                if (getpwuid(candidate))
                        goto next;
                if (getpwuid(candidate + UINT32_C(0xFFFE)))
                        goto next;
                if (getgrgid(candidate))
                        goto next;
                if (getgrgid(candidate + UINT32_C(0xFFFE)))
                        goto next;

                *ret_lock_file = lf;
                lf = (struct LockFile) LOCK_FILE_INIT;
                *shift = candidate;
                return 0;

        next:
                random_bytes(&candidate, sizeof(candidate));
                candidate = (candidate % (UID_SHIFT_PICK_MAX - UID_SHIFT_PICK_MIN)) + UID_SHIFT_PICK_MIN;
                candidate &= (uid_t) UINT32_C(0xFFFF0000);
        }
}

static int setup_uid_map(pid_t pid) {
        char uid_map[strlen("/proc//uid_map") + DECIMAL_STR_MAX(uid_t) + 1], line[DECIMAL_STR_MAX(uid_t)*3+3+1];
        int r;

        assert(pid > 1);

        xsprintf(uid_map, "/proc/" PID_FMT "/uid_map", pid);
        xsprintf(line, UID_FMT " " UID_FMT " " UID_FMT "\n", 0, arg_uid_shift, arg_uid_range);
        r = write_string_file(uid_map, line, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to write UID map: %m");

        /* We always assign the same UID and GID ranges */
        xsprintf(uid_map, "/proc/" PID_FMT "/gid_map", pid);
        r = write_string_file(uid_map, line, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to write GID map: %m");

        return 0;
}

static int nspawn_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        _cleanup_fdset_free_ FDSet *fds = NULL;
        char buf[NOTIFY_BUFFER_MAX+1];
        char *p = NULL;
        struct iovec iovec = {
                .iov_base = buf,
                .iov_len = sizeof(buf)-1,
        };
        union {
                struct cmsghdr cmsghdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct ucred)) +
                            CMSG_SPACE(sizeof(int) * NOTIFY_FD_MAX)];
        } control = {};
        struct msghdr msghdr = {
                .msg_iov = &iovec,
                .msg_iovlen = 1,
                .msg_control = &control,
                .msg_controllen = sizeof(control),
        };
        struct cmsghdr *cmsg;
        struct ucred *ucred = NULL;
        ssize_t n;
        pid_t inner_child_pid;
        _cleanup_strv_free_ char **tags = NULL;

        assert(userdata);

        inner_child_pid = PTR_TO_PID(userdata);

        if (revents != EPOLLIN) {
                log_warning("Got unexpected poll event for notify fd.");
                return 0;
        }

        n = recvmsg(fd, &msghdr, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (n < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                return log_warning_errno(errno, "Couldn't read notification socket: %m");
        }
        cmsg_close_all(&msghdr);

        CMSG_FOREACH(cmsg, &msghdr) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                           cmsg->cmsg_type == SCM_CREDENTIALS &&
                           cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {

                        ucred = (struct ucred*) CMSG_DATA(cmsg);
                }
        }

        if (!ucred || ucred->pid != inner_child_pid) {
                log_warning("Received notify message without valid credentials. Ignoring.");
                return 0;
        }

        if ((size_t) n >= sizeof(buf)) {
                log_warning("Received notify message exceeded maximum size. Ignoring.");
                return 0;
        }

        buf[n] = 0;
        tags = strv_split(buf, "\n\r");
        if (!tags)
                return log_oom();

        if (strv_find(tags, "READY=1"))
                sd_notifyf(false, "READY=1\n");

        p = strv_find_startswith(tags, "STATUS=");
        if (p)
                sd_notifyf(false, "STATUS=Container running: %s", p);

        return 0;
}

static int setup_sd_notify_parent(sd_event *event, int fd, pid_t *inner_child_pid) {
        int r;
        sd_event_source *notify_event_source;

        r = sd_event_add_io(event, &notify_event_source, fd, EPOLLIN, nspawn_dispatch_notify_fd, inner_child_pid);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate notify event source: %m");

        (void) sd_event_source_set_description(notify_event_source, "nspawn-notify");

        return 0;
}

static int load_settings(void) {
        _cleanup_(settings_freep) Settings *settings = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        const char *fn, *i;
        int r;

        /* If all settings are masked, there's no point in looking for
         * the settings file */
        if ((arg_settings_mask & _SETTINGS_MASK_ALL) == _SETTINGS_MASK_ALL)
                return 0;

        fn = strjoina(arg_machine, ".nspawn");

        /* We first look in the admin's directories in /etc and /run */
        FOREACH_STRING(i, "/etc/systemd/nspawn", "/run/systemd/nspawn") {
                _cleanup_free_ char *j = NULL;

                j = strjoin(i, "/", fn, NULL);
                if (!j)
                        return log_oom();

                f = fopen(j, "re");
                if (f) {
                        p = j;
                        j = NULL;

                        /* By default, we trust configuration from /etc and /run */
                        if (arg_settings_trusted < 0)
                                arg_settings_trusted = true;

                        break;
                }

                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", j);
        }

        if (!f) {
                /* After that, let's look for a file next to the
                 * actual image we shall boot. */

                if (arg_image) {
                        p = file_in_same_dir(arg_image, fn);
                        if (!p)
                                return log_oom();
                } else if (arg_directory) {
                        p = file_in_same_dir(arg_directory, fn);
                        if (!p)
                                return log_oom();
                }

                if (p) {
                        f = fopen(p, "re");
                        if (!f && errno != ENOENT)
                                return log_error_errno(errno, "Failed to open %s: %m", p);

                        /* By default, we do not trust configuration from /var/lib/machines */
                        if (arg_settings_trusted < 0)
                                arg_settings_trusted = false;
                }
        }

        if (!f)
                return 0;

        log_debug("Settings are trusted: %s", yes_no(arg_settings_trusted));

        r = settings_load(f, p, &settings);
        if (r < 0)
                return r;

        /* Copy over bits from the settings, unless they have been
         * explicitly masked by command line switches. */

        if ((arg_settings_mask & SETTING_START_MODE) == 0 &&
            settings->start_mode >= 0) {
                arg_start_mode = settings->start_mode;

                strv_free(arg_parameters);
                arg_parameters = settings->parameters;
                settings->parameters = NULL;
        }

        if ((arg_settings_mask & SETTING_WORKING_DIRECTORY) == 0 &&
            settings->working_directory) {
                free(arg_chdir);
                arg_chdir = settings->working_directory;
                settings->working_directory = NULL;
        }

        if ((arg_settings_mask & SETTING_ENVIRONMENT) == 0 &&
            settings->environment) {
                strv_free(arg_setenv);
                arg_setenv = settings->environment;
                settings->environment = NULL;
        }

        if ((arg_settings_mask & SETTING_USER) == 0 &&
            settings->user) {
                free(arg_user);
                arg_user = settings->user;
                settings->user = NULL;
        }

        if ((arg_settings_mask & SETTING_CAPABILITY) == 0) {
                uint64_t plus;

                plus = settings->capability;
                if (settings_private_network(settings))
                        plus |= (1ULL << CAP_NET_ADMIN);

                if (!arg_settings_trusted && plus != 0) {
                        if (settings->capability != 0)
                                log_warning("Ignoring Capability= setting, file %s is not trusted.", p);
                } else
                        arg_caps_retain |= plus;

                arg_caps_retain &= ~settings->drop_capability;
        }

        if ((arg_settings_mask & SETTING_KILL_SIGNAL) == 0 &&
            settings->kill_signal > 0)
                arg_kill_signal = settings->kill_signal;

        if ((arg_settings_mask & SETTING_PERSONALITY) == 0 &&
            settings->personality != PERSONALITY_INVALID)
                arg_personality = settings->personality;

        if ((arg_settings_mask & SETTING_MACHINE_ID) == 0 &&
            !sd_id128_is_null(settings->machine_id)) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring MachineID= setting, file %s is not trusted.", p);
                else
                        arg_uuid = settings->machine_id;
        }

        if ((arg_settings_mask & SETTING_READ_ONLY) == 0 &&
            settings->read_only >= 0)
                arg_read_only = settings->read_only;

        if ((arg_settings_mask & SETTING_VOLATILE_MODE) == 0 &&
            settings->volatile_mode != _VOLATILE_MODE_INVALID)
                arg_volatile_mode = settings->volatile_mode;

        if ((arg_settings_mask & SETTING_CUSTOM_MOUNTS) == 0 &&
            settings->n_custom_mounts > 0) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring TemporaryFileSystem=, Bind= and BindReadOnly= settings, file %s is not trusted.", p);
                else {
                        custom_mount_free_all(arg_custom_mounts, arg_n_custom_mounts);
                        arg_custom_mounts = settings->custom_mounts;
                        arg_n_custom_mounts = settings->n_custom_mounts;

                        settings->custom_mounts = NULL;
                        settings->n_custom_mounts = 0;
                }
        }

        if ((arg_settings_mask & SETTING_NETWORK) == 0 &&
            (settings->private_network >= 0 ||
             settings->network_veth >= 0 ||
             settings->network_bridge ||
             settings->network_zone ||
             settings->network_interfaces ||
             settings->network_macvlan ||
             settings->network_ipvlan ||
             settings->network_veth_extra)) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring network settings, file %s is not trusted.", p);
                else {
                        arg_network_veth = settings_network_veth(settings);
                        arg_private_network = settings_private_network(settings);

                        strv_free(arg_network_interfaces);
                        arg_network_interfaces = settings->network_interfaces;
                        settings->network_interfaces = NULL;

                        strv_free(arg_network_macvlan);
                        arg_network_macvlan = settings->network_macvlan;
                        settings->network_macvlan = NULL;

                        strv_free(arg_network_ipvlan);
                        arg_network_ipvlan = settings->network_ipvlan;
                        settings->network_ipvlan = NULL;

                        strv_free(arg_network_veth_extra);
                        arg_network_veth_extra = settings->network_veth_extra;
                        settings->network_veth_extra = NULL;

                        free(arg_network_bridge);
                        arg_network_bridge = settings->network_bridge;
                        settings->network_bridge = NULL;

                        free(arg_network_zone);
                        arg_network_zone = settings->network_zone;
                        settings->network_zone = NULL;
                }
        }

        if ((arg_settings_mask & SETTING_EXPOSE_PORTS) == 0 &&
            settings->expose_ports) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring Port= setting, file %s is not trusted.", p);
                else {
                        expose_port_free_all(arg_expose_ports);
                        arg_expose_ports = settings->expose_ports;
                        settings->expose_ports = NULL;
                }
        }

        if ((arg_settings_mask & SETTING_USERNS) == 0 &&
            settings->userns_mode != _USER_NAMESPACE_MODE_INVALID) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring PrivateUsers= and PrivateUsersChown= settings, file %s is not trusted.", p);
                else {
                        arg_userns_mode = settings->userns_mode;
                        arg_uid_shift = settings->uid_shift;
                        arg_uid_range = settings->uid_range;
                        arg_userns_chown = settings->userns_chown;
                }
        }

        if ((arg_settings_mask & SETTING_NOTIFY_READY) == 0)
                arg_notify_ready = settings->notify_ready;

        return 0;
}

int main(int argc, char *argv[]) {

        _cleanup_free_ char *device_path = NULL, *root_device = NULL, *home_device = NULL, *srv_device = NULL, *console = NULL;
        bool root_device_rw = true, home_device_rw = true, srv_device_rw = true;
        _cleanup_close_ int master = -1, image_fd = -1;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        int r, n_fd_passed, loop_nr = -1;
        char veth_name[IFNAMSIZ] = "";
        bool secondary = false, remove_subvol = false;
        sigset_t mask_chld;
        pid_t pid = 0;
        int ret = EXIT_SUCCESS;
        union in_addr_union exposed = {};
        _cleanup_release_lock_file_ LockFile tree_global_lock = LOCK_FILE_INIT, tree_local_lock = LOCK_FILE_INIT;
        bool interactive, veth_created = false;

        log_parse_environment();
        log_open();

        /* Make sure rename_process() in the stub init process can work */
        saved_argv = argv;
        saved_argc = argc;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (geteuid() != 0) {
                log_error("Need to be root.");
                r = -EPERM;
                goto finish;
        }
        r = determine_names();
        if (r < 0)
                goto finish;

        r = load_settings();
        if (r < 0)
                goto finish;

        r = verify_arguments();
        if (r < 0)
                goto finish;

        n_fd_passed = sd_listen_fds(false);
        if (n_fd_passed > 0) {
                r = fdset_new_listen_fds(&fds, false);
                if (r < 0) {
                        log_error_errno(r, "Failed to collect file descriptors: %m");
                        goto finish;
                }
        }

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
                        r = path_is_mount_point(arg_directory, 0);
                        if (r < 0) {
                                log_error_errno(r, "Failed to determine whether directory %s is mount point: %m", arg_directory);
                                goto finish;
                        }
                        if (r > 0)
                                r = tempfn_random_child(arg_directory, "machine.", &np);
                        else
                                r = tempfn_random(arg_directory, "machine.", &np);
                        if (r < 0) {
                                log_error_errno(r, "Failed to generate name for snapshot: %m");
                                goto finish;
                        }

                        r = image_path_lock(np, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r < 0) {
                                log_error_errno(r, "Failed to lock %s: %m", np);
                                goto finish;
                        }

                        r = btrfs_subvol_snapshot(arg_directory, np, (arg_read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) | BTRFS_SNAPSHOT_FALLBACK_COPY | BTRFS_SNAPSHOT_RECURSIVE | BTRFS_SNAPSHOT_QUOTA);
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
                                r = btrfs_subvol_snapshot(arg_template, arg_directory, (arg_read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) | BTRFS_SNAPSHOT_FALLBACK_COPY | BTRFS_SNAPSHOT_RECURSIVE | BTRFS_SNAPSHOT_QUOTA);
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

                if (arg_start_mode == START_BOOT) {
                        if (path_is_os_tree(arg_directory) <= 0) {
                                log_error("Directory %s doesn't look like an OS root directory (os-release file is missing). Refusing.", arg_directory);
                                r = -EINVAL;
                                goto finish;
                        }
                } else {
                        const char *p;

                        p = strjoina(arg_directory, "/usr/");
                        if (laccess(p, F_OK) < 0) {
                                log_error("Directory %s doesn't look like it has an OS tree. Refusing.", arg_directory);
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

        r = custom_mounts_prepare();
        if (r < 0)
                goto finish;

        interactive =
                isatty(STDIN_FILENO) > 0 &&
                isatty(STDOUT_FILENO) > 0;

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

        if (arg_selinux_apifs_context) {
                r = mac_selinux_apply(console, arg_selinux_apifs_context);
                if (r < 0)
                        goto finish;
        }

        if (unlockpt(master) < 0) {
                r = log_error_errno(errno, "Failed to unlock tty: %m");
                goto finish;
        }

        if (!arg_quiet)
                log_info("Spawning container %s on %s.\nPress ^] three times within 1s to kill container.",
                         arg_machine, arg_image ?: arg_directory);

        assert_se(sigprocmask_many(SIG_BLOCK, NULL, SIGCHLD, SIGWINCH, SIGTERM, SIGINT, -1) >= 0);

        assert_se(sigemptyset(&mask_chld) == 0);
        assert_se(sigaddset(&mask_chld, SIGCHLD) == 0);

        if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
                r = log_error_errno(errno, "Failed to become subreaper: %m");
                goto finish;
        }

        for (;;) {
                static const struct sigaction sa = {
                        .sa_handler = nop_signal_handler,
                        .sa_flags = SA_NOCLDSTOP,
                };

                _cleanup_release_lock_file_ LockFile uid_shift_lock = LOCK_FILE_INIT;
                _cleanup_close_ int etc_passwd_lock = -1;
                _cleanup_close_pair_ int
                        kmsg_socket_pair[2] = { -1, -1 },
                        rtnl_socket_pair[2] = { -1, -1 },
                        pid_socket_pair[2] = { -1, -1 },
                        uuid_socket_pair[2] = { -1, -1 },
                        notify_socket_pair[2] = { -1, -1 },
                        uid_shift_socket_pair[2] = { -1, -1 };
                _cleanup_close_ int notify_socket= -1;
                _cleanup_(barrier_destroy) Barrier barrier = BARRIER_NULL;
                _cleanup_(sd_event_unrefp) sd_event *event = NULL;
                _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
                _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
                ContainerStatus container_status;
                char last_char = 0;
                int ifi = 0;
                ssize_t l;

                if (arg_userns_mode == USER_NAMESPACE_PICK) {
                        /* When we shall pick the UID/GID range, let's first lock /etc/passwd, so that we can safely
                         * check with getpwuid() if the specific user already exists. Note that /etc might be
                         * read-only, in which case this will fail with EROFS. But that's really OK, as in that case we
                         * can be reasonably sure that no users are going to be added. Note that getpwuid() checks are
                         * really just an extra safety net. We kinda assume that the UID range we allocate from is
                         * really ours. */

                        etc_passwd_lock = take_etc_passwd_lock(NULL);
                        if (etc_passwd_lock < 0 && etc_passwd_lock != -EROFS) {
                                log_error_errno(r, "Failed to take /etc/passwd lock: %m");
                                goto finish;
                        }
                }

                r = barrier_create(&barrier);
                if (r < 0) {
                        log_error_errno(r, "Cannot initialize IPC barrier: %m");
                        goto finish;
                }

                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, kmsg_socket_pair) < 0) {
                        r = log_error_errno(errno, "Failed to create kmsg socket pair: %m");
                        goto finish;
                }

                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, rtnl_socket_pair) < 0) {
                        r = log_error_errno(errno, "Failed to create rtnl socket pair: %m");
                        goto finish;
                }

                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pid_socket_pair) < 0) {
                        r = log_error_errno(errno, "Failed to create pid socket pair: %m");
                        goto finish;
                }

                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, uuid_socket_pair) < 0) {
                        r = log_error_errno(errno, "Failed to create id socket pair: %m");
                        goto finish;
                }

                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, notify_socket_pair) < 0) {
                        r = log_error_errno(errno, "Failed to create notify socket pair: %m");
                        goto finish;
                }

                if (arg_userns_mode != USER_NAMESPACE_NO)
                        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, uid_shift_socket_pair) < 0) {
                                r = log_error_errno(errno, "Failed to create uid shift socket pair: %m");
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

                pid = raw_clone(SIGCHLD|CLONE_NEWNS);
                if (pid < 0) {
                        if (errno == EINVAL)
                                r = log_error_errno(errno, "clone() failed, do you have namespace support enabled in your kernel? (You need UTS, IPC, PID and NET namespacing built in): %m");
                        else
                                r = log_error_errno(errno, "clone() failed: %m");

                        goto finish;
                }

                if (pid == 0) {
                        /* The outer child only has a file system namespace. */
                        barrier_set_role(&barrier, BARRIER_CHILD);

                        master = safe_close(master);

                        kmsg_socket_pair[0] = safe_close(kmsg_socket_pair[0]);
                        rtnl_socket_pair[0] = safe_close(rtnl_socket_pair[0]);
                        pid_socket_pair[0] = safe_close(pid_socket_pair[0]);
                        uuid_socket_pair[0] = safe_close(uuid_socket_pair[0]);
                        notify_socket_pair[0] = safe_close(notify_socket_pair[0]);
                        uid_shift_socket_pair[0] = safe_close(uid_shift_socket_pair[0]);

                        (void) reset_all_signal_handlers();
                        (void) reset_signal_mask();

                        r = outer_child(&barrier,
                                        arg_directory,
                                        console,
                                        root_device, root_device_rw,
                                        home_device, home_device_rw,
                                        srv_device, srv_device_rw,
                                        interactive,
                                        secondary,
                                        pid_socket_pair[1],
                                        uuid_socket_pair[1],
                                        notify_socket_pair[1],
                                        kmsg_socket_pair[1],
                                        rtnl_socket_pair[1],
                                        uid_shift_socket_pair[1],
                                        fds);
                        if (r < 0)
                                _exit(EXIT_FAILURE);

                        _exit(EXIT_SUCCESS);
                }

                barrier_set_role(&barrier, BARRIER_PARENT);

                fds = fdset_free(fds);

                kmsg_socket_pair[1] = safe_close(kmsg_socket_pair[1]);
                rtnl_socket_pair[1] = safe_close(rtnl_socket_pair[1]);
                pid_socket_pair[1] = safe_close(pid_socket_pair[1]);
                uuid_socket_pair[1] = safe_close(uuid_socket_pair[1]);
                notify_socket_pair[1] = safe_close(notify_socket_pair[1]);
                uid_shift_socket_pair[1] = safe_close(uid_shift_socket_pair[1]);

                if (arg_userns_mode != USER_NAMESPACE_NO) {
                        /* The child just let us know the UID shift it might have read from the image. */
                        l = recv(uid_shift_socket_pair[0], &arg_uid_shift, sizeof(arg_uid_shift), 0);
                        if (l < 0) {
                                r = log_error_errno(errno, "Failed to read UID shift: %m");
                                goto finish;
                        }
                        if (l != sizeof(arg_uid_shift)) {
                                log_error("Short read while reading UID shift.");
                                r = EIO;
                                goto finish;
                        }

                        if (arg_userns_mode == USER_NAMESPACE_PICK) {
                                /* If we are supposed to pick the UID shift, let's try to use the shift read from the
                                 * image, but if that's already in use, pick a new one, and report back to the child,
                                 * which one we now picked. */

                                r = uid_shift_pick(&arg_uid_shift, &uid_shift_lock);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to pick suitable UID/GID range: %m");
                                        goto finish;
                                }

                                l = send(uid_shift_socket_pair[0], &arg_uid_shift, sizeof(arg_uid_shift), MSG_NOSIGNAL);
                                if (l < 0) {
                                        r = log_error_errno(errno, "Failed to send UID shift: %m");
                                        goto finish;
                                }
                                if (l != sizeof(arg_uid_shift)) {
                                        log_error("Short write while writing UID shift.");
                                        r = -EIO;
                                        goto finish;
                                }
                        }
                }

                /* Wait for the outer child. */
                r = wait_for_terminate_and_warn("namespace helper", pid, NULL);
                if (r < 0)
                        goto finish;
                if (r != 0) {
                        r = -EIO;
                        goto finish;
                }
                pid = 0;

                /* And now retrieve the PID of the inner child. */
                l = recv(pid_socket_pair[0], &pid, sizeof(pid), 0);
                if (l < 0) {
                        r = log_error_errno(errno, "Failed to read inner child PID: %m");
                        goto finish;
                }
                if (l != sizeof(pid)) {
                        log_error("Short read while reading inner child PID.");
                        r = EIO;
                        goto finish;
                }

                /* We also retrieve container UUID in case it was generated by outer child */
                l = recv(uuid_socket_pair[0], &arg_uuid, sizeof(arg_uuid), 0);
                if (l < 0) {
                        r = log_error_errno(errno, "Failed to read container machine ID: %m");
                        goto finish;
                }
                if (l != sizeof(arg_uuid)) {
                        log_error("Short read while reading container machined ID.");
                        r = EIO;
                        goto finish;
                }

                /* We also retrieve the socket used for notifications generated by outer child */
                notify_socket = receive_one_fd(notify_socket_pair[0], 0);
                if (notify_socket < 0) {
                        r = log_error_errno(errno, "Failed to receive notification socket from the outer child: %m");
                        goto finish;
                }

                log_debug("Init process invoked as PID " PID_FMT, pid);

                if (arg_userns_mode != USER_NAMESPACE_NO) {
                        if (!barrier_place_and_sync(&barrier)) { /* #1 */
                                log_error("Child died too early.");
                                r = -ESRCH;
                                goto finish;
                        }

                        r = setup_uid_map(pid);
                        if (r < 0)
                                goto finish;

                        (void) barrier_place(&barrier); /* #2 */
                }

                if (arg_private_network) {

                        r = move_network_interfaces(pid, arg_network_interfaces);
                        if (r < 0)
                                goto finish;

                        if (arg_network_veth) {
                                r = setup_veth(arg_machine, pid, veth_name,
                                               arg_network_bridge || arg_network_zone);
                                if (r < 0)
                                        goto finish;
                                else if (r > 0)
                                        ifi = r;

                                if (arg_network_bridge) {
                                        /* Add the interface to a bridge */
                                        r = setup_bridge(veth_name, arg_network_bridge, false);
                                        if (r < 0)
                                                goto finish;
                                        if (r > 0)
                                                ifi = r;
                                } else if (arg_network_zone) {
                                        /* Add the interface to a bridge, possibly creating it */
                                        r = setup_bridge(veth_name, arg_network_zone, true);
                                        if (r < 0)
                                                goto finish;
                                        if (r > 0)
                                                ifi = r;
                                }
                        }

                        r = setup_veth_extra(arg_machine, pid, arg_network_veth_extra);
                        if (r < 0)
                                goto finish;

                        /* We created the primary and extra veth links now; let's remember this, so that we know to
                           remove them later on. Note that we don't bother with removing veth links that were created
                           here when their setup failed half-way, because in that case the kernel should be able to
                           remove them on its own, since they cannot be referenced by anything yet. */
                        veth_created = true;

                        r = setup_macvlan(arg_machine, pid, arg_network_macvlan);
                        if (r < 0)
                                goto finish;

                        r = setup_ipvlan(arg_machine, pid, arg_network_ipvlan);
                        if (r < 0)
                                goto finish;
                }

                if (arg_register) {
                        r = register_machine(
                                        arg_machine,
                                        pid,
                                        arg_directory,
                                        arg_uuid,
                                        ifi,
                                        arg_slice,
                                        arg_custom_mounts, arg_n_custom_mounts,
                                        arg_kill_signal,
                                        arg_property,
                                        arg_keep_unit,
                                        arg_container_service_name);
                        if (r < 0)
                                goto finish;
                }

                r = sync_cgroup(pid, arg_unified_cgroup_hierarchy);
                if (r < 0)
                        goto finish;

                if (arg_keep_unit) {
                        r = create_subcgroup(pid, arg_unified_cgroup_hierarchy);
                        if (r < 0)
                                goto finish;
                }

                r = chown_cgroup(pid, arg_uid_shift);
                if (r < 0)
                        goto finish;

                /* Notify the child that the parent is ready with all
                 * its setup (including cgroup-ification), and that
                 * the child can now hand over control to the code to
                 * run inside the container. */
                (void) barrier_place(&barrier); /* #3 */

                /* Block SIGCHLD here, before notifying child.
                 * process_pty() will handle it with the other signals. */
                assert_se(sigprocmask(SIG_BLOCK, &mask_chld, NULL) >= 0);

                /* Reset signal to default */
                r = default_signals(SIGCHLD, -1);
                if (r < 0) {
                        log_error_errno(r, "Failed to reset SIGCHLD: %m");
                        goto finish;
                }

                r = sd_event_new(&event);
                if (r < 0) {
                        log_error_errno(r, "Failed to get default event source: %m");
                        goto finish;
                }

                r = setup_sd_notify_parent(event, notify_socket, PID_TO_PTR(pid));
                if (r < 0)
                        goto finish;

                /* Let the child know that we are ready and wait that the child is completely ready now. */
                if (!barrier_place_and_sync(&barrier)) { /* #4 */
                        log_error("Child died too early.");
                        r = -ESRCH;
                        goto finish;
                }

                /* At this point we have made use of the UID we picked, and thus nss-mymachines will make them appear
                 * in getpwuid(), thus we can release the /etc/passwd lock. */
                etc_passwd_lock = safe_close(etc_passwd_lock);

                sd_notifyf(false,
                           "STATUS=Container running.\n"
                           "X_NSPAWN_LEADER_PID=" PID_FMT, pid);
                if (!arg_notify_ready)
                        sd_notify(false, "READY=1\n");

                if (arg_kill_signal > 0) {
                        /* Try to kill the init system on SIGINT or SIGTERM */
                        sd_event_add_signal(event, NULL, SIGINT, on_orderly_shutdown, PID_TO_PTR(pid));
                        sd_event_add_signal(event, NULL, SIGTERM, on_orderly_shutdown, PID_TO_PTR(pid));
                } else {
                        /* Immediately exit */
                        sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
                        sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
                }

                /* simply exit on sigchld */
                sd_event_add_signal(event, NULL, SIGCHLD, NULL, NULL);

                if (arg_expose_ports) {
                        r = expose_port_watch_rtnl(event, rtnl_socket_pair[0], on_address_change, &exposed, &rtnl);
                        if (r < 0)
                                goto finish;

                        (void) expose_port_execute(rtnl, arg_expose_ports, &exposed);
                }

                rtnl_socket_pair[0] = safe_close(rtnl_socket_pair[0]);

                r = pty_forward_new(event, master, PTY_FORWARD_IGNORE_VHANGUP | (interactive ? 0 : PTY_FORWARD_READ_ONLY), &forward);
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
                if (arg_register && !arg_keep_unit)
                        terminate_machine(pid);

                /* Normally redundant, but better safe than sorry */
                kill(pid, SIGKILL);

                r = wait_for_container(pid, &container_status);
                pid = 0;

                if (r < 0)
                        /* We failed to wait for the container, or the
                         * container exited abnormally */
                        goto finish;
                else if (r > 0 || container_status == CONTAINER_TERMINATED) {
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

                expose_port_flush(arg_expose_ports, &exposed);

                (void) remove_veth_links(veth_name, arg_network_veth_extra);
                veth_created = false;
        }

finish:
        sd_notify(false,
                  "STOPPING=1\n"
                  "STATUS=Terminating...");

        if (pid > 0)
                kill(pid, SIGKILL);

        /* Try to flush whatever is still queued in the pty */
        if (master >= 0)
                (void) copy_bytes(master, STDOUT_FILENO, (uint64_t) -1, false);

        loop_remove(loop_nr, &image_fd);

        if (remove_subvol && arg_directory) {
                int k;

                k = btrfs_subvol_remove(arg_directory, BTRFS_REMOVE_RECURSIVE|BTRFS_REMOVE_QUOTA);
                if (k < 0)
                        log_warning_errno(k, "Cannot remove subvolume '%s', ignoring: %m", arg_directory);
        }

        if (arg_machine) {
                const char *p;

                p = strjoina("/run/systemd/nspawn/propagate/", arg_machine);
                (void) rm_rf(p, REMOVE_ROOT);
        }

        expose_port_flush(arg_expose_ports, &exposed);

        if (veth_created)
                (void) remove_veth_links(veth_name, arg_network_veth_extra);
        (void) remove_bridge(arg_network_zone);

        free(arg_directory);
        free(arg_template);
        free(arg_image);
        free(arg_machine);
        free(arg_user);
        free(arg_chdir);
        strv_free(arg_setenv);
        free(arg_network_bridge);
        strv_free(arg_network_interfaces);
        strv_free(arg_network_macvlan);
        strv_free(arg_network_ipvlan);
        strv_free(arg_network_veth_extra);
        strv_free(arg_parameters);
        custom_mount_free_all(arg_custom_mounts, arg_n_custom_mounts);
        expose_port_free_all(arg_expose_ports);

        return r < 0 ? EXIT_FAILURE : ret;
}
