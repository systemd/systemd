/* SPDX-License-Identifier: LGPL-2.1+ */

#if HAVE_BLKID
#include <blkid.h>
#endif
#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <pwd.h>
#include <sched.h>
#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "barrier.h"
#include "base-filesystem.h"
#include "blkid-util.h"
#include "btrfs-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "cap-list.h"
#include "capability-util.h"
#include "cgroup-util.h"
#include "copy.h"
#include "cpu-set-util.h"
#include "dev-setup.h"
#include "dissect-image.h"
#include "env-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "log.h"
#include "loop-util.h"
#include "loopback-setup.h"
#include "machine-image.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "netlink-util.h"
#include "nspawn-cgroup.h"
#include "nspawn-def.h"
#include "nspawn-expose-ports.h"
#include "nspawn-mount.h"
#include "nspawn-network.h"
#include "nspawn-patch-uid.h"
#include "nspawn-register.h"
#include "nspawn-seccomp.h"
#include "nspawn-settings.h"
#include "nspawn-setuid.h"
#include "nspawn-stub-pid1.h"
#include "os-util.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "ptyfwd.h"
#include "random-util.h"
#include "raw-clone.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "util.h"

#if HAVE_SPLIT_USR
#define STATIC_RESOLV_CONF "/lib/systemd/resolv.conf"
#else
#define STATIC_RESOLV_CONF "/usr/lib/systemd/resolv.conf"
#endif

/* nspawn is listening on the socket at the path in the constant nspawn_notify_socket_path
 * nspawn_notify_socket_path is relative to the container
 * the init process in the container pid can send messages to nspawn following the sd_notify(3) protocol */
#define NSPAWN_NOTIFY_SOCKET_PATH "/run/systemd/nspawn/notify"

#define EXIT_FORCE_RESTART 133

typedef enum ContainerStatus {
        CONTAINER_TERMINATED,
        CONTAINER_REBOOTED
} ContainerStatus;

static char *arg_directory = NULL;
static char *arg_template = NULL;
static char *arg_chdir = NULL;
static char *arg_pivot_root_new = NULL;
static char *arg_pivot_root_old = NULL;
static char *arg_user = NULL;
static sd_id128_t arg_uuid = {};
static char *arg_machine = NULL;     /* The name used by the host to refer to this */
static char *arg_hostname = NULL;    /* The name the payload sees by default */
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
static size_t arg_n_custom_mounts = 0;
static char **arg_setenv = NULL;
static bool arg_quiet = false;
static bool arg_register = true;
static bool arg_keep_unit = false;
static char **arg_network_interfaces = NULL;
static char **arg_network_macvlan = NULL;
static char **arg_network_ipvlan = NULL;
static bool arg_network_veth = false;
static char **arg_network_veth_extra = NULL;
static char *arg_network_bridge = NULL;
static char *arg_network_zone = NULL;
static char *arg_network_namespace_path = NULL;
static unsigned long arg_personality = PERSONALITY_INVALID;
static char *arg_image = NULL;
static VolatileMode arg_volatile_mode = VOLATILE_NO;
static ExposePort *arg_expose_ports = NULL;
static char **arg_property = NULL;
static UserNamespaceMode arg_userns_mode = USER_NAMESPACE_NO;
static uid_t arg_uid_shift = UID_INVALID, arg_uid_range = 0x10000U;
static bool arg_userns_chown = false;
static int arg_kill_signal = 0;
static CGroupUnified arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_UNKNOWN;
static SettingsMask arg_settings_mask = 0;
static int arg_settings_trusted = -1;
static char **arg_parameters = NULL;
static const char *arg_container_service_name = "systemd-nspawn";
static bool arg_notify_ready = false;
static bool arg_use_cgns = true;
static unsigned long arg_clone_ns_flags = CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS;
static MountSettingsMask arg_mount_settings = MOUNT_APPLY_APIVFS_RO|MOUNT_APPLY_TMPFS_TMP;
static void *arg_root_hash = NULL;
static size_t arg_root_hash_size = 0;
static char **arg_syscall_whitelist = NULL;
static char **arg_syscall_blacklist = NULL;
static struct rlimit *arg_rlimit[_RLIMIT_MAX] = {};
static bool arg_no_new_privileges = false;
static int arg_oom_score_adjust = 0;
static bool arg_oom_score_adjust_set = false;
static cpu_set_t *arg_cpuset = NULL;
static unsigned arg_cpuset_ncpus = 0;
static ResolvConfMode arg_resolv_conf = RESOLV_CONF_AUTO;
static TimezoneMode arg_timezone = TIMEZONE_AUTO;

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        (void) pager_open(false);

        r = terminal_urlify_man("systemd-nspawn", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [OPTIONS...] [PATH] [ARGUMENTS...]\n\n"
               "Spawn a command or OS in a light-weight container.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "  -q --quiet                Do not show status information\n"
               "  -D --directory=PATH       Root directory for the container\n"
               "     --template=PATH        Initialize root directory from template directory,\n"
               "                            if missing\n"
               "  -x --ephemeral            Run container with snapshot of root directory, and\n"
               "                            remove it after exit\n"
               "  -i --image=PATH           File system device or disk image for the container\n"
               "     --root-hash=HASH       Specify verity root hash\n"
               "  -a --as-pid2              Maintain a stub init as PID1, invoke binary as PID2\n"
               "  -b --boot                 Boot up full system (i.e. invoke init)\n"
               "     --chdir=PATH           Set working directory in the container\n"
               "     --pivot-root=PATH[:PATH]\n"
               "                            Pivot root to given directory in the container\n"
               "  -u --user=USER            Run the command under specified user or uid\n"
               "  -M --machine=NAME         Set the machine name for the container\n"
               "     --hostname=NAME        Override the hostname for the container\n"
               "     --uuid=UUID            Set a specific machine UUID for the container\n"
               "  -S --slice=SLICE          Place the container in the specified slice\n"
               "     --property=NAME=VALUE  Set scope unit property\n"
               "  -U --private-users=pick   Run within user namespace, autoselect UID/GID range\n"
               "     --private-users[=UIDBASE[:NUIDS]]\n"
               "                            Similar, but with user configured UID/GID range\n"
               "     --private-users-chown  Adjust OS tree ownership to private UID/GID range\n"
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
               "                            Add a virtual Ethernet connection to the container\n"
               "                            and attach it to an existing bridge on the host\n"
               "     --network-zone=NAME    Similar, but attach the new interface to an\n"
               "                            an automatically managed bridge interface\n"
               "     --network-namespace-path=PATH\n"
               "                            Set network namespace to the one represented by\n"
               "                            the specified kernel namespace file node\n"
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
               "     --system-call-filter=LIST|~LIST\n"
               "                            Permit/prohibit specific system calls\n"
               "     --rlimit=NAME=LIMIT    Set a resource limit for the payload\n"
               "     --oom-score-adjust=VALUE\n"
               "                            Adjust the OOM score value for the payload\n"
               "     --cpu-affinity=CPUS    Adjust the CPU affinity of the container\n"
               "     --kill-signal=SIGNAL   Select signal to use for shutting down PID 1\n"
               "     --link-journal=MODE    Link up guest journal, one of no, auto, guest, \n"
               "                            host, try-guest, try-host\n"
               "  -j                        Equivalent to --link-journal=try-guest\n"
               "     --resolv-conf=MODE     Select mode of /etc/resolv.conf initialization\n"
               "     --timezone=MODE        Select mode of /etc/localtime initialization\n"
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
               "     --register=BOOLEAN     Register container as machine\n"
               "     --keep-unit            Do not register a scope for the machine, reuse\n"
               "                            the service unit nspawn is running in\n"
               "     --volatile[=MODE]      Run the system in volatile mode\n"
               "     --settings=BOOLEAN     Load additional settings from .nspawn file\n"
               "     --notify-ready=BOOLEAN Receive notifications from the child init process\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link
        );

        return 0;
}

static int custom_mount_check_all(void) {
        size_t i;

        for (i = 0; i < arg_n_custom_mounts; i++) {
                CustomMount *m = &arg_custom_mounts[i];

                if (path_equal(m->destination, "/") && arg_userns_mode != USER_NAMESPACE_NO) {
                        if (arg_userns_chown)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--private-users-chown may not be combined with custom root mounts.");
                        else if (arg_uid_shift == UID_INVALID)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--private-users with automatic UID shift may not be combined with custom root mounts.");
                }
        }

        return 0;
}

static int detect_unified_cgroup_hierarchy_from_environment(void) {
        const char *e;
        int r;

        /* Allow the user to control whether the unified hierarchy is used */
        e = getenv("UNIFIED_CGROUP_HIERARCHY");
        if (e) {
                r = parse_boolean(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $UNIFIED_CGROUP_HIERARCHY.");
                if (r > 0)
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_ALL;
                else
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;
        }

        return 0;
}

static int detect_unified_cgroup_hierarchy_from_image(const char *directory) {
        int r;

        /* Let's inherit the mode to use from the host system, but let's take into consideration what systemd in the
         * image actually supports. */
        r = cg_all_unified();
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether we are in all unified mode.");
        if (r > 0) {
                /* Unified cgroup hierarchy support was added in 230. Unfortunately the detection
                 * routine only detects 231, so we'll have a false negative here for 230. */
                r = systemd_installation_has_version(directory, 230);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine systemd version in container: %m");
                if (r > 0)
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_ALL;
                else
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;
        } else if (cg_unified_controller(SYSTEMD_CGROUP_CONTROLLER) > 0) {
                /* Mixed cgroup hierarchy support was added in 233 */
                r = systemd_installation_has_version(directory, 233);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine systemd version in container: %m");
                if (r > 0)
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_SYSTEMD;
                else
                        arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;
        } else
                arg_unified_cgroup_hierarchy = CGROUP_UNIFIED_NONE;

        log_debug("Using %s hierarchy for container.",
                  arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_NONE ? "legacy" :
                  arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_SYSTEMD ? "hybrid" : "unified");

        return 0;
}

static void parse_share_ns_env(const char *name, unsigned long ns_flag) {
        int r;

        r = getenv_bool(name);
        if (r == -ENXIO)
                return;
        if (r < 0)
                log_warning_errno(r, "Failed to parse %s from environment, defaulting to false.", name);
        arg_clone_ns_flags = (arg_clone_ns_flags & ~ns_flag) | (r > 0 ? 0 : ns_flag);
}

static void parse_mount_settings_env(void) {
        const char *e;
        int r;

        r = getenv_bool("SYSTEMD_NSPAWN_TMPFS_TMP");
        if (r >= 0)
                SET_FLAG(arg_mount_settings, MOUNT_APPLY_TMPFS_TMP, r > 0);
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $SYSTEMD_NSPAWN_TMPFS_TMP, ignoring: %m");

        e = getenv("SYSTEMD_NSPAWN_API_VFS_WRITABLE");
        if (!e)
                return;

        if (streq(e, "network")) {
                arg_mount_settings |= MOUNT_APPLY_APIVFS_RO|MOUNT_APPLY_APIVFS_NETNS;
                return;
        }

        r = parse_boolean(e);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse SYSTEMD_NSPAWN_API_VFS_WRITABLE from environment, ignoring.");
                return;
        }

        SET_FLAG(arg_mount_settings, MOUNT_APPLY_APIVFS_RO, r == 0);
        SET_FLAG(arg_mount_settings, MOUNT_APPLY_APIVFS_NETNS, false);
}

static void parse_environment(void) {
        const char *e;
        int r;

        parse_share_ns_env("SYSTEMD_NSPAWN_SHARE_NS_IPC", CLONE_NEWIPC);
        parse_share_ns_env("SYSTEMD_NSPAWN_SHARE_NS_PID", CLONE_NEWPID);
        parse_share_ns_env("SYSTEMD_NSPAWN_SHARE_NS_UTS", CLONE_NEWUTS);
        parse_share_ns_env("SYSTEMD_NSPAWN_SHARE_SYSTEM", CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS);

        parse_mount_settings_env();

        /* SYSTEMD_NSPAWN_USE_CGNS=0 can be used to disable CLONE_NEWCGROUP use,
         * even if it is supported. If not supported, it has no effect. */
        r = getenv_bool("SYSTEMD_NSPAWN_USE_CGNS");
        if (r == 0 || !cg_ns_supported())
                arg_use_cgns = false;

        e = getenv("SYSTEMD_NSPAWN_CONTAINER_SERVICE");
        if (e)
                arg_container_service_name = e;

        detect_unified_cgroup_hierarchy_from_environment();
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
                ARG_NETWORK_NAMESPACE_PATH,
                ARG_PERSONALITY,
                ARG_VOLATILE,
                ARG_TEMPLATE,
                ARG_PROPERTY,
                ARG_PRIVATE_USERS,
                ARG_KILL_SIGNAL,
                ARG_SETTINGS,
                ARG_CHDIR,
                ARG_PIVOT_ROOT,
                ARG_PRIVATE_USERS_CHOWN,
                ARG_NOTIFY_READY,
                ARG_ROOT_HASH,
                ARG_SYSTEM_CALL_FILTER,
                ARG_RLIMIT,
                ARG_HOSTNAME,
                ARG_NO_NEW_PRIVILEGES,
                ARG_OOM_SCORE_ADJUST,
                ARG_CPU_AFFINITY,
                ARG_RESOLV_CONF,
                ARG_TIMEZONE,
        };

        static const struct option options[] = {
                { "help",                   no_argument,       NULL, 'h'                        },
                { "version",                no_argument,       NULL, ARG_VERSION                },
                { "directory",              required_argument, NULL, 'D'                        },
                { "template",               required_argument, NULL, ARG_TEMPLATE               },
                { "ephemeral",              no_argument,       NULL, 'x'                        },
                { "user",                   required_argument, NULL, 'u'                        },
                { "private-network",        no_argument,       NULL, ARG_PRIVATE_NETWORK        },
                { "as-pid2",                no_argument,       NULL, 'a'                        },
                { "boot",                   no_argument,       NULL, 'b'                        },
                { "uuid",                   required_argument, NULL, ARG_UUID                   },
                { "read-only",              no_argument,       NULL, ARG_READ_ONLY              },
                { "capability",             required_argument, NULL, ARG_CAPABILITY             },
                { "drop-capability",        required_argument, NULL, ARG_DROP_CAPABILITY        },
                { "no-new-privileges",      required_argument, NULL, ARG_NO_NEW_PRIVILEGES      },
                { "link-journal",           required_argument, NULL, ARG_LINK_JOURNAL           },
                { "bind",                   required_argument, NULL, ARG_BIND                   },
                { "bind-ro",                required_argument, NULL, ARG_BIND_RO                },
                { "tmpfs",                  required_argument, NULL, ARG_TMPFS                  },
                { "overlay",                required_argument, NULL, ARG_OVERLAY                },
                { "overlay-ro",             required_argument, NULL, ARG_OVERLAY_RO             },
                { "machine",                required_argument, NULL, 'M'                        },
                { "hostname",               required_argument, NULL, ARG_HOSTNAME               },
                { "slice",                  required_argument, NULL, 'S'                        },
                { "setenv",                 required_argument, NULL, 'E'                        },
                { "selinux-context",        required_argument, NULL, 'Z'                        },
                { "selinux-apifs-context",  required_argument, NULL, 'L'                        },
                { "quiet",                  no_argument,       NULL, 'q'                        },
                { "share-system",           no_argument,       NULL, ARG_SHARE_SYSTEM           }, /* not documented */
                { "register",               required_argument, NULL, ARG_REGISTER               },
                { "keep-unit",              no_argument,       NULL, ARG_KEEP_UNIT              },
                { "network-interface",      required_argument, NULL, ARG_NETWORK_INTERFACE      },
                { "network-macvlan",        required_argument, NULL, ARG_NETWORK_MACVLAN        },
                { "network-ipvlan",         required_argument, NULL, ARG_NETWORK_IPVLAN         },
                { "network-veth",           no_argument,       NULL, 'n'                        },
                { "network-veth-extra",     required_argument, NULL, ARG_NETWORK_VETH_EXTRA     },
                { "network-bridge",         required_argument, NULL, ARG_NETWORK_BRIDGE         },
                { "network-zone",           required_argument, NULL, ARG_NETWORK_ZONE           },
                { "network-namespace-path", required_argument, NULL, ARG_NETWORK_NAMESPACE_PATH },
                { "personality",            required_argument, NULL, ARG_PERSONALITY            },
                { "image",                  required_argument, NULL, 'i'                        },
                { "volatile",               optional_argument, NULL, ARG_VOLATILE               },
                { "port",                   required_argument, NULL, 'p'                        },
                { "property",               required_argument, NULL, ARG_PROPERTY               },
                { "private-users",          optional_argument, NULL, ARG_PRIVATE_USERS          },
                { "private-users-chown",    optional_argument, NULL, ARG_PRIVATE_USERS_CHOWN    },
                { "kill-signal",            required_argument, NULL, ARG_KILL_SIGNAL            },
                { "settings",               required_argument, NULL, ARG_SETTINGS               },
                { "chdir",                  required_argument, NULL, ARG_CHDIR                  },
                { "pivot-root",             required_argument, NULL, ARG_PIVOT_ROOT             },
                { "notify-ready",           required_argument, NULL, ARG_NOTIFY_READY           },
                { "root-hash",              required_argument, NULL, ARG_ROOT_HASH              },
                { "system-call-filter",     required_argument, NULL, ARG_SYSTEM_CALL_FILTER     },
                { "rlimit",                 required_argument, NULL, ARG_RLIMIT                 },
                { "oom-score-adjust",       required_argument, NULL, ARG_OOM_SCORE_ADJUST       },
                { "cpu-affinity",           required_argument, NULL, ARG_CPU_AFFINITY           },
                { "resolv-conf",            required_argument, NULL, ARG_RESOLV_CONF            },
                { "timezone",               required_argument, NULL, ARG_TIMEZONE               },
                {}
        };

        int c, r;
        const char *p;
        uint64_t plus = 0, minus = 0;
        bool mask_all_settings = false, mask_no_settings = false;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hD:u:abL:M:jS:Z:qi:xp:nUE:", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        return help();

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
                        arg_settings_mask |= SETTING_EPHEMERAL;
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

                        free_and_replace(arg_network_zone, j);

                        arg_network_veth = true;
                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;
                }

                case ARG_NETWORK_BRIDGE:

                        if (!ifname_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Bridge interface name not valid: %s", optarg);

                        r = free_and_strdup(&arg_network_bridge, optarg);
                        if (r < 0)
                                return log_oom();

                        _fallthrough_;
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
                        if (!ifname_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Network interface name not valid: %s", optarg);

                        if (strv_extend(&arg_network_interfaces, optarg) < 0)
                                return log_oom();

                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_MACVLAN:

                        if (!ifname_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "MACVLAN network interface name not valid: %s", optarg);

                        if (strv_extend(&arg_network_macvlan, optarg) < 0)
                                return log_oom();

                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_IPVLAN:

                        if (!ifname_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "IPVLAN network interface name not valid: %s", optarg);

                        if (strv_extend(&arg_network_ipvlan, optarg) < 0)
                                return log_oom();

                        _fallthrough_;
                case ARG_PRIVATE_NETWORK:
                        arg_private_network = true;
                        arg_settings_mask |= SETTING_NETWORK;
                        break;

                case ARG_NETWORK_NAMESPACE_PATH:
                        r = parse_path_argument_and_warn(optarg, false, &arg_network_namespace_path);
                        if (r < 0)
                                return r;

                        break;

                case 'b':
                        if (arg_start_mode == START_PID2)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--boot and --as-pid2 may not be combined.");

                        arg_start_mode = START_BOOT;
                        arg_settings_mask |= SETTING_START_MODE;
                        break;

                case 'a':
                        if (arg_start_mode == START_BOOT)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--boot and --as-pid2 may not be combined.");

                        arg_start_mode = START_PID2;
                        arg_settings_mask |= SETTING_START_MODE;
                        break;

                case ARG_UUID:
                        r = sd_id128_from_string(optarg, &arg_uuid);
                        if (r < 0)
                                return log_error_errno(r, "Invalid UUID: %s", optarg);

                        if (sd_id128_is_null(arg_uuid))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Machine UUID may not be all zeroes.");

                        arg_settings_mask |= SETTING_MACHINE_ID;
                        break;

                case 'S':
                        arg_slice = optarg;
                        break;

                case 'M':
                        if (isempty(optarg))
                                arg_machine = mfree(arg_machine);
                        else {
                                if (!machine_name_is_valid(optarg))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Invalid machine name: %s", optarg);

                                r = free_and_strdup(&arg_machine, optarg);
                                if (r < 0)
                                        return log_oom();
                        }
                        break;

                case ARG_HOSTNAME:
                        if (isempty(optarg))
                                arg_hostname = mfree(arg_hostname);
                        else {
                                if (!hostname_is_valid(optarg, false))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Invalid hostname: %s", optarg);

                                r = free_and_strdup(&arg_hostname, optarg);
                                if (r < 0)
                                        return log_oom();
                        }

                        arg_settings_mask |= SETTING_HOSTNAME;
                        break;

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
                                        r = capability_from_name(t);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse capability %s.", t);

                                        if (c == ARG_CAPABILITY)
                                                plus |= 1ULL << r;
                                        else
                                                minus |= 1ULL << r;
                                }
                        }

                        arg_settings_mask |= SETTING_CAPABILITY;
                        break;
                }

                case ARG_NO_NEW_PRIVILEGES:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --no-new-privileges= argument: %s", optarg);

                        arg_no_new_privileges = r;
                        arg_settings_mask |= SETTING_NO_NEW_PRIVILEGES;
                        break;

                case 'j':
                        arg_link_journal = LINK_GUEST;
                        arg_link_journal_try = true;
                        arg_settings_mask |= SETTING_LINK_JOURNAL;
                        break;

                case ARG_LINK_JOURNAL:
                        r = parse_link_journal(optarg, &arg_link_journal, &arg_link_journal_try);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse link journal mode %s", optarg);
                                return -EINVAL;
                        }

                        arg_settings_mask |= SETTING_LINK_JOURNAL;
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
                case ARG_OVERLAY_RO:
                        r = overlay_mount_parse(&arg_custom_mounts, &arg_n_custom_mounts, optarg, c == ARG_OVERLAY_RO);
                        if (r == -EADDRNOTAVAIL)
                                return log_error_errno(r, "--overlay(-ro)= needs at least two colon-separated directories specified.");
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --overlay(-ro)= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_CUSTOM_MOUNTS;
                        break;

                case 'E': {
                        char **n;

                        if (!env_assignment_is_valid(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Environment variable assignment '%s' is not valid.", optarg);

                        n = strv_env_set(arg_setenv, optarg);
                        if (!n)
                                return log_oom();

                        strv_free_and_replace(arg_setenv, n);
                        arg_settings_mask |= SETTING_ENVIRONMENT;
                        break;
                }

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_SHARE_SYSTEM:
                        /* We don't officially support this anymore, except for compat reasons. People should use the
                         * $SYSTEMD_NSPAWN_SHARE_* environment variables instead. */
                        log_warning("Please do not use --share-system anymore, use $SYSTEMD_NSPAWN_SHARE_* instead.");
                        arg_clone_ns_flags = 0;
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
                        if (arg_personality == PERSONALITY_INVALID)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown or unsupported personality '%s'.", optarg);

                        arg_settings_mask |= SETTING_PERSONALITY;
                        break;

                case ARG_VOLATILE:

                        if (!optarg)
                                arg_volatile_mode = VOLATILE_YES;
                        else if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(volatile_mode, VolatileMode, _VOLATILE_MODE_MAX);
                                return 0;
                        } else {
                                VolatileMode m;

                                m = volatile_mode_from_string(optarg);
                                if (m < 0)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Failed to parse --volatile= argument: %s", optarg);
                                else
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

                case ARG_PRIVATE_USERS: {
                        int boolean = -1;

                        if (!optarg)
                                boolean = true;
                        else if (!in_charset(optarg, DIGITS))
                                /* do *not* parse numbers as booleans */
                                boolean = parse_boolean(optarg);

                        if (boolean == false) {
                                /* no: User namespacing off */
                                arg_userns_mode = USER_NAMESPACE_NO;
                                arg_uid_shift = UID_INVALID;
                                arg_uid_range = UINT32_C(0x10000);
                        } else if (boolean == true) {
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
                                        r = safe_atou32(range, &arg_uid_range);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to parse UID range \"%s\": %m", range);
                                } else
                                        shift = optarg;

                                r = parse_uid(shift, &arg_uid_shift);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse UID \"%s\": %m", optarg);

                                arg_userns_mode = USER_NAMESPACE_FIXED;
                        }

                        if (arg_uid_range <= 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "UID range cannot be 0.");

                        arg_settings_mask |= SETTING_USERNS;
                        break;
                }

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
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(signal, int, _NSIG);
                                return 0;
                        }

                        arg_kill_signal = signal_from_string(optarg);
                        if (arg_kill_signal < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Cannot parse signal: %s", optarg);

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
                        if (!path_is_absolute(optarg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Working directory %s is not an absolute path.", optarg);

                        r = free_and_strdup(&arg_chdir, optarg);
                        if (r < 0)
                                return log_oom();

                        arg_settings_mask |= SETTING_WORKING_DIRECTORY;
                        break;

                case ARG_PIVOT_ROOT:
                        r = pivot_root_parse(&arg_pivot_root_new, &arg_pivot_root_old, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --pivot-root= argument %s: %m", optarg);

                        arg_settings_mask |= SETTING_PIVOT_ROOT;
                        break;

                case ARG_NOTIFY_READY:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "%s is not a valid notify mode. Valid modes are: yes, no, and ready.", optarg);
                        arg_notify_ready = r;
                        arg_settings_mask |= SETTING_NOTIFY_READY;
                        break;

                case ARG_ROOT_HASH: {
                        void *k;
                        size_t l;

                        r = unhexmem(optarg, strlen(optarg), &k, &l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse root hash: %s", optarg);
                        if (l < sizeof(sd_id128_t)) {
                                log_error("Root hash must be at least 128bit long: %s", optarg);
                                free(k);
                                return -EINVAL;
                        }

                        free(arg_root_hash);
                        arg_root_hash = k;
                        arg_root_hash_size = l;
                        break;
                }

                case ARG_SYSTEM_CALL_FILTER: {
                        bool negative;
                        const char *items;

                        negative = optarg[0] == '~';
                        items = negative ? optarg + 1 : optarg;

                        for (;;) {
                                _cleanup_free_ char *word = NULL;

                                r = extract_first_word(&items, &word, NULL, 0);
                                if (r == 0)
                                        break;
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse system call filter: %m");

                                if (negative)
                                        r = strv_extend(&arg_syscall_blacklist, word);
                                else
                                        r = strv_extend(&arg_syscall_whitelist, word);
                                if (r < 0)
                                        return log_oom();
                        }

                        arg_settings_mask |= SETTING_SYSCALL_FILTER;
                        break;
                }

                case ARG_RLIMIT: {
                        const char *eq;
                        char *name;
                        int rl;

                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(rlimit, int, _RLIMIT_MAX);
                                return 0;
                        }

                        eq = strchr(optarg, '=');
                        if (!eq)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--rlimit= expects an '=' assignment.");

                        name = strndup(optarg, eq - optarg);
                        if (!name)
                                return log_oom();

                        rl = rlimit_from_string_harder(name);
                        if (rl < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Unknown resource limit: %s", name);

                        if (!arg_rlimit[rl]) {
                                arg_rlimit[rl] = new0(struct rlimit, 1);
                                if (!arg_rlimit[rl])
                                        return log_oom();
                        }

                        r = rlimit_parse(rl, eq + 1, arg_rlimit[rl]);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse resource limit: %s", eq + 1);

                        arg_settings_mask |= SETTING_RLIMIT_FIRST << rl;
                        break;
                }

                case ARG_OOM_SCORE_ADJUST:
                        r = parse_oom_score_adjust(optarg, &arg_oom_score_adjust);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --oom-score-adjust= parameter: %s", optarg);

                        arg_oom_score_adjust_set = true;
                        arg_settings_mask |= SETTING_OOM_SCORE_ADJUST;
                        break;

                case ARG_CPU_AFFINITY: {
                        _cleanup_cpu_free_ cpu_set_t *cpuset = NULL;

                        r = parse_cpu_set(optarg, &cpuset);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse CPU affinity mask: %s", optarg);

                        if (arg_cpuset)
                                CPU_FREE(arg_cpuset);

                        arg_cpuset = TAKE_PTR(cpuset);
                        arg_cpuset_ncpus = r;
                        arg_settings_mask |= SETTING_CPU_AFFINITY;
                        break;
                }

                case ARG_RESOLV_CONF:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(resolv_conf_mode, ResolvConfMode, _RESOLV_CONF_MODE_MAX);
                                return 0;
                        }

                        arg_resolv_conf = resolv_conf_mode_from_string(optarg);
                        if (arg_resolv_conf < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse /etc/resolv.conf mode: %s", optarg);

                        arg_settings_mask |= SETTING_RESOLV_CONF;
                        break;

                case ARG_TIMEZONE:
                        if (streq(optarg, "help")) {
                                DUMP_STRING_TABLE(timezone_mode, TimezoneMode, _TIMEZONE_MODE_MAX);
                                return 0;
                        }

                        arg_timezone = timezone_mode_from_string(optarg);
                        if (arg_timezone < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Failed to parse /etc/localtime mode: %s", optarg);

                        arg_settings_mask |= SETTING_TIMEZONE;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc > optind) {
                strv_free(arg_parameters);
                arg_parameters = strv_copy(argv + optind);
                if (!arg_parameters)
                        return log_oom();

                arg_settings_mask |= SETTING_START_MODE;
        }

        if (arg_ephemeral && arg_template && !arg_directory)
                /* User asked for ephemeral execution but specified --template= instead of --directory=. Semantically
                 * such an invocation makes some sense, see https://github.com/systemd/systemd/issues/3667. Let's
                 * accept this here, and silently make "--ephemeral --template=" equivalent to "--ephemeral
                 * --directory=". */
                arg_directory = TAKE_PTR(arg_template);

        arg_caps_retain = (arg_caps_retain | plus | (arg_private_network ? 1ULL << CAP_NET_ADMIN : 0)) & ~minus;

        /* Load all settings from .nspawn files */
        if (mask_no_settings)
                arg_settings_mask = 0;

        /* Don't load any settings from .nspawn files */
        if (mask_all_settings)
                arg_settings_mask = _SETTINGS_MASK_ALL;

        return 1;
}

static int verify_arguments(void) {
        int r;

        if (arg_userns_mode != USER_NAMESPACE_NO)
                arg_mount_settings |= MOUNT_USE_USERNS;

        if (arg_private_network)
                arg_mount_settings |= MOUNT_APPLY_APIVFS_NETNS;

        if (!(arg_clone_ns_flags & CLONE_NEWPID) ||
            !(arg_clone_ns_flags & CLONE_NEWUTS)) {
                arg_register = false;
                if (arg_start_mode != START_PID1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--boot cannot be used without namespacing.");
        }

        if (arg_userns_mode == USER_NAMESPACE_PICK)
                arg_userns_chown = true;

        if (arg_start_mode == START_BOOT && arg_kill_signal <= 0)
                arg_kill_signal = SIGRTMIN+3;

        if (arg_keep_unit && arg_register && cg_pid_get_owner_uid(0, NULL) >= 0)
                /* Save the user from accidentally registering either user-$SESSION.scope or user@.service.
                 * The latter is not technically a user session, but we don't need to labour the point. */
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--keep-unit --register=yes may not be used when invoked from a user session.");

        if (arg_directory && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--directory= and --image= may not be combined.");

        if (arg_template && arg_image)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--template= and --image= may not be combined.");

        if (arg_template && !(arg_directory || arg_machine))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--template= needs --directory= or --machine=.");

        if (arg_ephemeral && arg_template)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--ephemeral and --template= may not be combined.");

        if (arg_ephemeral && !IN_SET(arg_link_journal, LINK_NO, LINK_AUTO))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--ephemeral and --link-journal= may not be combined.");

        if (arg_userns_mode != USER_NAMESPACE_NO && !userns_supported())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--private-users= is not supported, kernel compiled without user namespace support.");

        if (arg_userns_chown && arg_read_only)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--read-only and --private-users-chown may not be combined.");

        /* If --network-namespace-path is given with any other network-related option,
         * we need to error out, to avoid conflicts between different network options. */
        if (arg_network_namespace_path &&
                (arg_network_interfaces || arg_network_macvlan ||
                 arg_network_ipvlan || arg_network_veth_extra ||
                 arg_network_bridge || arg_network_zone ||
                 arg_network_veth || arg_private_network))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--network-namespace-path cannot be combined with other network options.");

        if (arg_network_bridge && arg_network_zone)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--network-bridge= and --network-zone= may not be combined.");

        if (arg_userns_mode != USER_NAMESPACE_NO && (arg_mount_settings & MOUNT_APPLY_APIVFS_NETNS) && !arg_private_network)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid namespacing settings. Mounting sysfs with --private-users requires --private-network.");

        if (arg_userns_mode != USER_NAMESPACE_NO && !(arg_mount_settings & MOUNT_APPLY_APIVFS_RO))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot combine --private-users with read-write mounts.");

        if (arg_volatile_mode != VOLATILE_NO && arg_read_only)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot combine --read-only with --volatile. Note that --volatile already implies a read-only base hierarchy.");

        if (arg_expose_ports && !arg_private_network)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot use --port= without private networking.");

#if ! HAVE_LIBIPTC
        if (arg_expose_ports)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--port= is not supported, compiled without libiptc support.");
#endif

        r = custom_mount_check_all();
        if (r < 0)
                return r;

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
        int r;

        q = prefix_roota(root, path);
        r = mkdir_errno_wrapper(q, mode);
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        return userns_lchown(q, uid, gid);
}

static const char *timezone_from_path(const char *path) {
        return PATH_STARTSWITH_SET(
                        path,
                        "../usr/share/zoneinfo/",
                        "/usr/share/zoneinfo/");
}

static int setup_timezone(const char *dest) {
        _cleanup_free_ char *p = NULL, *etc = NULL;
        const char *where, *check;
        TimezoneMode m;
        int r;

        assert(dest);

        if (IN_SET(arg_timezone, TIMEZONE_AUTO, TIMEZONE_SYMLINK)) {
                r = readlink_malloc("/etc/localtime", &p);
                if (r == -ENOENT && arg_timezone == TIMEZONE_AUTO)
                        m = arg_read_only && arg_volatile_mode != VOLATILE_YES ? TIMEZONE_OFF : TIMEZONE_DELETE;
                else if (r == -EINVAL && arg_timezone == TIMEZONE_AUTO) /* regular file? */
                        m = arg_read_only && arg_volatile_mode != VOLATILE_YES ? TIMEZONE_BIND : TIMEZONE_COPY;
                else if (r < 0) {
                        log_warning_errno(r, "Failed to read host's /etc/localtime symlink, not updating container timezone: %m");
                        /* To handle warning, delete /etc/localtime and replace it with a symbolic link to a time zone data
                         * file.
                         *
                         * Example:
                         * ln -s /usr/share/zoneinfo/UTC /etc/localtime
                         */
                        return 0;
                } else if (arg_timezone == TIMEZONE_AUTO)
                        m = arg_read_only && arg_volatile_mode != VOLATILE_YES ? TIMEZONE_BIND : TIMEZONE_SYMLINK;
                else
                        m = arg_timezone;
        } else
                m = arg_timezone;

        if (m == TIMEZONE_OFF)
                return 0;

        r = chase_symlinks("/etc", dest, CHASE_PREFIX_ROOT, &etc);
        if (r < 0) {
                log_warning_errno(r, "Failed to resolve /etc path in container, ignoring: %m");
                return 0;
        }

        where = strjoina(etc, "/localtime");

        switch (m) {

        case TIMEZONE_DELETE:
                if (unlink(where) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno, "Failed to remove '%s', ignoring: %m", where);

                return 0;

        case TIMEZONE_SYMLINK: {
                _cleanup_free_ char *q = NULL;
                const char *z, *what;

                z = timezone_from_path(p);
                if (!z) {
                        log_warning("/etc/localtime does not point into /usr/share/zoneinfo/, not updating container timezone.");
                        return 0;
                }

                r = readlink_malloc(where, &q);
                if (r >= 0 && streq_ptr(timezone_from_path(q), z))
                        return 0; /* Already pointing to the right place? Then do nothing .. */

                check = strjoina(dest, "/usr/share/zoneinfo/", z);
                r = chase_symlinks(check, dest, 0, NULL);
                if (r < 0)
                        log_debug_errno(r, "Timezone %s does not exist (or is not accessible) in container, not creating symlink: %m", z);
                else {
                        if (unlink(where) < 0 && errno != ENOENT) {
                                log_full_errno(IN_SET(errno, EROFS, EACCES, EPERM) ? LOG_DEBUG : LOG_WARNING, /* Don't complain on read-only images */
                                               errno, "Failed to remove existing timezone info %s in container, ignoring: %m", where);
                                return 0;
                        }

                        what = strjoina("../usr/share/zoneinfo/", z);
                        if (symlink(what, where) < 0) {
                                log_full_errno(IN_SET(errno, EROFS, EACCES, EPERM) ? LOG_DEBUG : LOG_WARNING,
                                               errno, "Failed to correct timezone of container, ignoring: %m");
                                return 0;
                        }

                        break;
                }

                _fallthrough_;
        }

        case TIMEZONE_BIND: {
                _cleanup_free_ char *resolved = NULL;
                int found;

                found = chase_symlinks(where, dest, CHASE_NONEXISTENT, &resolved);
                if (found < 0) {
                        log_warning_errno(found, "Failed to resolve /etc/localtime path in container, ignoring: %m");
                        return 0;
                }

                if (found == 0) /* missing? */
                        (void) touch(resolved);

                r = mount_verbose(LOG_WARNING, "/etc/localtime", resolved, NULL, MS_BIND, NULL);
                if (r >= 0)
                        return mount_verbose(LOG_ERR, NULL, resolved, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV, NULL);

                _fallthrough_;
        }

        case TIMEZONE_COPY:
                /* If mounting failed, try to copy */
                r = copy_file_atomic("/etc/localtime", where, 0644, 0, COPY_REFLINK|COPY_REPLACE);
                if (r < 0) {
                        log_full_errno(IN_SET(r, -EROFS, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING, r,
                                       "Failed to copy /etc/localtime to %s, ignoring: %m", where);
                        return 0;
                }

                break;

        default:
                assert_not_reached("unexpected mode");
        }

        /* Fix permissions of the symlink or file copy we just created */
        r = userns_lchown(where, 0, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to chown /etc/localtime, ignoring: %m");

        return 0;
}

static int have_resolv_conf(const char *path) {
        assert(path);

        if (access(path, F_OK) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_debug_errno(errno, "Failed to determine whether '%s' is available: %m", path);
        }

        return 1;
}

static int resolved_listening(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *dns_stub_listener_mode = NULL;
        int r;

        /* Check if resolved is listening */

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_debug_errno(r, "Failed to open system bus: %m");

        r = bus_name_has_owner(bus, "org.freedesktop.resolve1", NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to check whether the 'org.freedesktop.resolve1' bus name is taken: %m");
        if (r == 0)
                return 0;

        r = sd_bus_get_property_string(bus,
                                       "org.freedesktop.resolve1",
                                       "/org/freedesktop/resolve1",
                                       "org.freedesktop.resolve1.Manager",
                                       "DNSStubListener",
                                       &error,
                                       &dns_stub_listener_mode);
        if (r < 0)
                return log_debug_errno(r, "Failed to query DNSStubListener property: %s", bus_error_message(&error, r));

        return STR_IN_SET(dns_stub_listener_mode, "udp", "yes");
}

static int setup_resolv_conf(const char *dest) {
        _cleanup_free_ char *etc = NULL;
        const char *where, *what;
        ResolvConfMode m;
        int r;

        assert(dest);

        if (arg_resolv_conf == RESOLV_CONF_AUTO) {
                if (arg_private_network)
                        m = RESOLV_CONF_OFF;
                else if (have_resolv_conf(STATIC_RESOLV_CONF) > 0 && resolved_listening() > 0)
                        m = arg_read_only && arg_volatile_mode != VOLATILE_YES ? RESOLV_CONF_BIND_STATIC : RESOLV_CONF_COPY_STATIC;
                else if (have_resolv_conf("/etc/resolv.conf") > 0)
                        m = arg_read_only && arg_volatile_mode != VOLATILE_YES ? RESOLV_CONF_BIND_HOST : RESOLV_CONF_COPY_HOST;
                else
                        m = arg_read_only && arg_volatile_mode != VOLATILE_YES ? RESOLV_CONF_OFF : RESOLV_CONF_DELETE;
        } else
                m = arg_resolv_conf;

        if (m == RESOLV_CONF_OFF)
                return 0;

        r = chase_symlinks("/etc", dest, CHASE_PREFIX_ROOT, &etc);
        if (r < 0) {
                log_warning_errno(r, "Failed to resolve /etc path in container, ignoring: %m");
                return 0;
        }

        where = strjoina(etc, "/resolv.conf");

        if (m == RESOLV_CONF_DELETE) {
                if (unlink(where) < 0)
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno, "Failed to remove '%s', ignoring: %m", where);

                return 0;
        }

        if (IN_SET(m, RESOLV_CONF_BIND_STATIC, RESOLV_CONF_COPY_STATIC))
                what = STATIC_RESOLV_CONF;
        else
                what = "/etc/resolv.conf";

        if (IN_SET(m, RESOLV_CONF_BIND_HOST, RESOLV_CONF_BIND_STATIC)) {
                _cleanup_free_ char *resolved = NULL;
                int found;

                found = chase_symlinks(where, dest, CHASE_NONEXISTENT, &resolved);
                if (found < 0) {
                        log_warning_errno(found, "Failed to resolve /etc/resolv.conf path in container, ignoring: %m");
                        return 0;
                }

                if (found == 0) /* missing? */
                        (void) touch(resolved);

                r = mount_verbose(LOG_WARNING, what, resolved, NULL, MS_BIND, NULL);
                if (r >= 0)
                        return mount_verbose(LOG_ERR, NULL, resolved, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV, NULL);
        }

        /* If that didn't work, let's copy the file */
        r = copy_file(what, where, O_TRUNC|O_NOFOLLOW, 0644, 0, COPY_REFLINK);
        if (r < 0) {
                /* If the file already exists as symlink, let's suppress the warning, under the assumption that
                 * resolved or something similar runs inside and the symlink points there.
                 *
                 * If the disk image is read-only, there's also no point in complaining.
                 */
                log_full_errno(!IN_SET(RESOLV_CONF_COPY_HOST, RESOLV_CONF_COPY_STATIC) && IN_SET(r, -ELOOP, -EROFS, -EACCES, -EPERM) ? LOG_DEBUG : LOG_WARNING, r,
                               "Failed to copy /etc/resolv.conf to %s, ignoring: %m", where);
                return 0;
        }

        r = userns_lchown(where, 0, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to chown /etc/resolv.conf, ignoring: %m");

        return 0;
}

static int setup_boot_id(void) {
        _cleanup_(unlink_and_freep) char *from = NULL;
        _cleanup_free_ char *path = NULL;
        sd_id128_t rnd = SD_ID128_NULL;
        const char *to;
        int r;

        /* Generate a new randomized boot ID, so that each boot-up of
         * the container gets a new one */

        r = tempfn_random_child(NULL, "proc-sys-kernel-random-boot-id", &path);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random boot ID path: %m");

        r = sd_id128_randomize(&rnd);
        if (r < 0)
                return log_error_errno(r, "Failed to generate random boot id: %m");

        r = id128_write(path, ID128_UUID, rnd, false);
        if (r < 0)
                return log_error_errno(r, "Failed to write boot id: %m");

        from = TAKE_PTR(path);
        to = "/proc/sys/kernel/random/boot_id";

        r = mount_verbose(LOG_ERR, from, to, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        return mount_verbose(LOG_ERR, NULL, to, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
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
                if (!from)
                        return log_oom();

                to = prefix_root(dest, from);
                if (!to)
                        return log_oom();

                if (stat(from, &st) < 0) {

                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to stat %s: %m", from);

                } else if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "%s is not a char or block device, cannot copy.", from);
                else {
                        _cleanup_free_ char *sl = NULL, *prefixed = NULL, *dn = NULL, *t = NULL;

                        if (mknod(to, st.st_mode, st.st_rdev) < 0) {
                                /* Explicitly warn the user when /dev is already populated. */
                                if (errno == EEXIST)
                                        log_notice("%s/dev is pre-mounted and pre-populated. If a pre-mounted /dev is provided it needs to be an unpopulated file system.", dest);
                                if (errno != EPERM)
                                        return log_error_errno(errno, "mknod(%s) failed: %m", to);

                                /* Some systems abusively restrict mknod but allow bind mounts. */
                                r = touch(to);
                                if (r < 0)
                                        return log_error_errno(r, "touch (%s) failed: %m", to);
                                r = mount_verbose(LOG_DEBUG, from, to, NULL, MS_BIND, NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Both mknod and bind mount (%s) failed: %m", to);
                        }

                        r = userns_lchown(to, 0, 0);
                        if (r < 0)
                                return log_error_errno(r, "chown() of device node %s failed: %m", to);

                        dn = strjoin("/dev/", S_ISCHR(st.st_mode) ? "char" : "block");
                        if (!dn)
                                return log_oom();

                        r = userns_mkdir(dest, dn, 0755, 0, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create '%s': %m", dn);

                        if (asprintf(&sl, "%s/%u:%u", dn, major(st.st_rdev), minor(st.st_rdev)) < 0)
                                return log_oom();

                        prefixed = prefix_root(dest, sl);
                        if (!prefixed)
                                return log_oom();

                        t = strjoin("../", d);
                        if (!t)
                                return log_oom();

                        if (symlink(t, prefixed) < 0)
                                log_debug_errno(errno, "Failed to symlink '%s' to '%s': %m", t, prefixed);
                }
        }

        return r;
}

static int setup_pts(const char *dest) {
        _cleanup_free_ char *options = NULL;
        const char *p;
        int r;

#if HAVE_SELINUX
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
        r = mkdir_errno_wrapper(p, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create /dev/pts: %m");

        r = mount_verbose(LOG_ERR, "devpts", p, "devpts", MS_NOSUID|MS_NOEXEC, options);
        if (r < 0)
                return r;
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

        return mount_verbose(LOG_ERR, console, to, NULL, MS_BIND, NULL);
}

static int setup_keyring(void) {
        key_serial_t keyring;

        /* Allocate a new session keyring for the container. This makes sure the keyring of the session systemd-nspawn
         * was invoked from doesn't leak into the container. Note that by default we block keyctl() and request_key()
         * anyway via seccomp so doing this operation isn't strictly necessary, but in case people explicitly whitelist
         * these system calls let's make sure we don't leak anything into the container. */

        keyring = keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0);
        if (keyring == -1) {
                if (errno == ENOSYS)
                        log_debug_errno(errno, "Kernel keyring not supported, ignoring.");
                else if (IN_SET(errno, EACCES, EPERM))
                        log_debug_errno(errno, "Kernel keyring access prohibited, ignoring.");
                else
                        return log_error_errno(errno, "Setting up kernel keyring failed: %m");
        }

        return 0;
}

static int setup_kmsg(int kmsg_socket) {
        _cleanup_(unlink_and_freep) char *from = NULL;
        _cleanup_free_ char *fifo = NULL;
        _cleanup_close_ int fd = -1;
        _cleanup_umask_ mode_t u;
        const char *to;
        int r;

        assert(kmsg_socket >= 0);

        u = umask(0000);

        /* We create the kmsg FIFO as as temporary file in /tmp, but immediately delete it after bind mounting it to
         * /proc/kmsg. While FIFOs on the reading side behave very similar to /proc/kmsg, their writing side behaves
         * differently from /dev/kmsg in that writing blocks when nothing is reading. In order to avoid any problems
         * with containers deadlocking due to this we simply make /dev/kmsg unavailable to the container. */

        r = tempfn_random_child(NULL, "proc-kmsg", &fifo);
        if (r < 0)
                return log_error_errno(r, "Failed to generate kmsg path: %m");

        if (mkfifo(fifo, 0600) < 0)
                return log_error_errno(errno, "mkfifo() for /run/kmsg failed: %m");

        from = TAKE_PTR(fifo);
        to = "/proc/kmsg";

        r = mount_verbose(LOG_ERR, from, to, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        fd = open(from, O_RDWR|O_NONBLOCK|O_CLOEXEC);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open fifo: %m");

        /* Store away the fd in the socket, so that it stays open as long as we run the child */
        r = send_one_fd(kmsg_socket, fd, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to send FIFO fd: %m");

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
        int r;

        if ((arg_clone_ns_flags & CLONE_NEWUTS) == 0)
                return 0;

        r = sethostname_idempotent(arg_hostname ?: arg_machine);
        if (r < 0)
                return log_error_errno(r, "Failed to set hostname: %m");

        return 0;
}

static int setup_journal(const char *directory) {
        _cleanup_free_ char *d = NULL;
        const char *dirname, *p, *q;
        sd_id128_t this_id;
        char id[33];
        bool try;
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

        FOREACH_STRING(dirname, "/var", "/var/log", "/var/log/journal") {
                r = userns_mkdir(directory, dirname, 0755, 0, 0);
                if (r < 0) {
                        bool ignore = r == -EROFS && try;
                        log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r,
                                       "Failed to create %s%s: %m", dirname, ignore ? ", ignoring" : "");
                        return ignore ? 0 : r;
                }
        }

        (void) sd_id128_to_string(arg_uuid, id);

        p = strjoina("/var/log/journal/", id);
        q = prefix_roota(directory, p);

        if (path_is_mount_point(p, NULL, 0) > 0) {
                if (try)
                        return 0;

                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "%s: already a mount point, refusing to use for journal", p);
        }

        if (path_is_mount_point(q, NULL, 0) > 0) {
                if (try)
                        return 0;

                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "%s: already a mount point, refusing to use for journal", q);
        }

        r = readlink_and_make_absolute(p, &d);
        if (r >= 0) {
                if (IN_SET(arg_link_journal, LINK_GUEST, LINK_AUTO) &&
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

                r = mkdir_errno_wrapper(p, 0755);
                if (r < 0 && r != -EEXIST) {
                        if (try) {
                                log_debug_errno(r, "Failed to create %s, skipping journal setup: %m", p);
                                return 0;
                        } else
                                return log_error_errno(r, "Failed to create %s: %m", p);
                }

        } else if (access(p, F_OK) < 0)
                return 0;

        if (dir_is_empty(q) == 0)
                log_warning("%s is not empty, proceeding anyway.", q);

        r = userns_mkdir(directory, p, 0755, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create %s: %m", q);

        r = mount_verbose(LOG_DEBUG, p, q, NULL, MS_BIND, NULL);
        if (r < 0)
                return log_error_errno(errno, "Failed to bind mount journal from host into guest: %m");

        return 0;
}

static int drop_capabilities(void) {
        return capability_bounding_set_drop(arg_caps_retain, false);
}

static int reset_audit_loginuid(void) {
        _cleanup_free_ char *p = NULL;
        int r;

        if ((arg_clone_ns_flags & CLONE_NEWPID) == 0)
                return 0;

        r = read_one_line_file("/proc/self/loginuid", &p);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to read /proc/self/loginuid: %m");

        /* Already reset? */
        if (streq(p, "4294967295"))
                return 0;

        r = write_string_file("/proc/self/loginuid", "4294967295", WRITE_STRING_FILE_DISABLE_BUFFER);
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
        r = mount_verbose(LOG_ERR, p, q, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        r = mount_verbose(LOG_ERR, NULL, q, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
        if (r < 0)
                return r;

        /* machined will MS_MOVE into that directory, and that's only
         * supported for non-shared mounts. */
        return mount_verbose(LOG_ERR, NULL, q, NULL, MS_SLAVE, NULL);
}

static int setup_machine_id(const char *directory) {
        const char *etc_machine_id;
        sd_id128_t id;
        int r;

        /* If the UUID in the container is already set, then that's what counts, and we use. If it isn't set, and the
         * caller passed --uuid=, then we'll pass it in the $container_uuid env var to PID 1 of the container. The
         * assumption is that PID 1 will then write it to /etc/machine-id to make it persistent. If --uuid= is not
         * passed we generate a random UUID, and pass it via $container_uuid. In effect this means that /etc/machine-id
         * in the container and our idea of the container UUID will always be in sync (at least if PID 1 in the
         * container behaves nicely). */

        etc_machine_id = prefix_roota(directory, "/etc/machine-id");

        r = id128_read(etc_machine_id, ID128_PLAIN, &id);
        if (r < 0) {
                if (!IN_SET(r, -ENOENT, -ENOMEDIUM)) /* If the file is missing or empty, we don't mind */
                        return log_error_errno(r, "Failed to read machine ID from container image: %m");

                if (sd_id128_is_null(arg_uuid)) {
                        r = sd_id128_randomize(&arg_uuid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to acquire randomized machine UUID: %m");
                }
        } else {
                if (sd_id128_is_null(id))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Machine ID in container image is zero, refusing.");

                arg_uuid = id;
        }

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

                _fallthrough_;
        case CLD_DUMPED:
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Container %s terminated by signal %s.", arg_machine, signal_to_string(status.si_status));

        default:
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Container %s failed due to unknown reason.", arg_machine);
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

static int on_sigchld(sd_event_source *s, const struct signalfd_siginfo *ssi, void *userdata) {
        pid_t pid;

        assert(s);
        assert(ssi);

        pid = PTR_TO_PID(userdata);

        for (;;) {
                siginfo_t si = {};

                if (waitid(P_ALL, 0, &si, WNOHANG|WNOWAIT|WEXITED) < 0)
                        return log_error_errno(errno, "Failed to waitid(): %m");
                if (si.si_pid == 0) /* No pending children. */
                        break;
                if (si.si_pid == pid) {
                        /* The main process we care for has exited. Return from
                         * signal handler but leave the zombie. */
                        sd_event_exit(sd_event_source_get_event(s), 0);
                        break;
                }

                /* Reap all other children. */
                (void) waitid(P_PID, si.si_pid, &si, WNOHANG|WEXITED);
        }

        return 0;
}

static int on_request_stop(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        pid_t pid;

        assert(m);

        pid = PTR_TO_PID(userdata);

        if (arg_kill_signal > 0) {
                log_info("Container termination requested. Attempting to halt container.");
                (void) kill(pid, arg_kill_signal);
        } else {
                log_info("Container termination requested. Exiting.");
                sd_event_exit(sd_bus_get_event(sd_bus_message_get_bus(m)), 0);
        }

        return 0;
}

static int determine_names(void) {
        int r;

        if (arg_template && !arg_directory && arg_machine) {

                /* If --template= was specified then we should not
                 * search for a machine, but instead create a new one
                 * in /var/lib/machine. */

                arg_directory = strjoin("/var/lib/machines/", arg_machine);
                if (!arg_directory)
                        return log_oom();
        }

        if (!arg_image && !arg_directory) {
                if (arg_machine) {
                        _cleanup_(image_unrefp) Image *i = NULL;

                        r = image_find(IMAGE_MACHINE, arg_machine, &i);
                        if (r == -ENOENT)
                                return log_error_errno(r, "No image for machine '%s'.", arg_machine);
                        if (r < 0)
                                return log_error_errno(r, "Failed to find image for machine '%s': %m", arg_machine);

                        if (IN_SET(i->type, IMAGE_RAW, IMAGE_BLOCK))
                                r = free_and_strdup(&arg_image, i->path);
                        else
                                r = free_and_strdup(&arg_directory, i->path);
                        if (r < 0)
                                return log_oom();

                        if (!arg_ephemeral)
                                arg_read_only = arg_read_only || i->read_only;
                } else {
                        r = safe_getcwd(&arg_directory);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine current directory: %m");
                }

                if (!arg_directory && !arg_image) {
                        log_error("Failed to determine path, please use -D or -i.");
                        return -EINVAL;
                }
        }

        if (!arg_machine) {
                if (arg_directory && path_equal(arg_directory, "/"))
                        arg_machine = gethostname_malloc();
                else {
                        if (arg_image) {
                                char *e;

                                arg_machine = strdup(basename(arg_image));

                                /* Truncate suffix if there is one */
                                e = endswith(arg_machine, ".raw");
                                if (e)
                                        *e = 0;
                        } else
                                arg_machine = strdup(basename(arg_directory));
                }
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

static int chase_symlinks_and_update(char **p, unsigned flags) {
        char *chased;
        int r;

        assert(p);

        if (!*p)
                return 0;

        r = chase_symlinks(*p, NULL, flags, &chased);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve path %s: %m", *p);

        free_and_replace(*p, chased);
        return r; /* r might be an fd here in case we ever use CHASE_OPEN in flags */
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

                if (arg_uid_shift != (st.st_gid & UINT32_C(0xffff0000)))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "UID and GID base of %s don't match.", directory);

                arg_uid_range = UINT32_C(0x10000);
        }

        if (arg_uid_shift > (uid_t) -1 - arg_uid_range)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "UID base too high for UID range.");

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
        size_t n_env = 1;
        const char *envp[] = {
                "PATH=" DEFAULT_PATH_COMPAT,
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
        const char *exec_target;
        _cleanup_strv_free_ char **env_use = NULL;
        int r;

        /* This is the "inner" child process, i.e. the one forked off by the "outer" child process, which is the one
         * the container manager itself forked off. At the time of clone() it gained its own CLONE_NEWNS, CLONE_NEWPID,
         * CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER namespaces. Note that it has its own CLONE_NEWNS namespace,
         * separate from the CLONE_NEWNS created for the "outer" child, and also separate from the host's CLONE_NEWNS
         * namespace. The reason for having two levels of CLONE_NEWNS namespaces is that the "inner" one is owned by
         * the CLONE_NEWUSER namespace of the container, while the "outer" one is owned by the host's CLONE_NEWUSER
         * namespace.
         *
         * Note at this point we have no CLONE_NEWNET namespace yet. We'll acquire that one later through
         * unshare(). See below. */

        assert(barrier);
        assert(directory);
        assert(kmsg_socket >= 0);

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                /* Tell the parent, that it now can write the UID map. */
                (void) barrier_place(barrier); /* #1 */

                /* Wait until the parent wrote the UID map */
                if (!barrier_place_and_sync(barrier)) /* #2 */
                        return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                               "Parent died too early");
        }

        r = reset_uid_gid();
        if (r < 0)
                return log_error_errno(r, "Couldn't become new root: %m");

        r = mount_all(NULL,
                      arg_mount_settings | MOUNT_IN_USERNS,
                      arg_uid_shift,
                      arg_selinux_apifs_context);
        if (r < 0)
                return r;

        if (!arg_network_namespace_path && arg_private_network) {
                r = unshare(CLONE_NEWNET);
                if (r < 0)
                        return log_error_errno(errno, "Failed to unshare network namespace: %m");

                /* Tell the parent that it can setup network interfaces. */
                (void) barrier_place(barrier); /* #3 */
        }

        r = mount_sysfs(NULL, arg_mount_settings);
        if (r < 0)
                return r;

        /* Wait until we are cgroup-ified, so that we
         * can mount the right cgroup path writable */
        if (!barrier_place_and_sync(barrier)) /* #4 */
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "Parent died too early");

        if (arg_use_cgns) {
                r = unshare(CLONE_NEWCGROUP);
                if (r < 0)
                        return log_error_errno(errno, "Failed to unshare cgroup namespace: %m");
                r = mount_cgroups(
                                "",
                                arg_unified_cgroup_hierarchy,
                                arg_userns_mode != USER_NAMESPACE_NO,
                                arg_uid_shift,
                                arg_uid_range,
                                arg_selinux_apifs_context,
                                true);
                if (r < 0)
                        return r;
        } else {
                r = mount_systemd_cgroup_writable("", arg_unified_cgroup_hierarchy);
                if (r < 0)
                        return r;
        }

        r = setup_boot_id();
        if (r < 0)
                return r;

        r = setup_kmsg(kmsg_socket);
        if (r < 0)
                return r;
        kmsg_socket = safe_close(kmsg_socket);

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

        if (arg_oom_score_adjust_set) {
                r = set_oom_score_adjust(arg_oom_score_adjust);
                if (r < 0)
                        return log_error_errno(r, "Failed to adjust OOM score: %m");
        }

        if (arg_cpuset)
                if (sched_setaffinity(0, CPU_ALLOC_SIZE(arg_cpuset_ncpus), arg_cpuset) < 0)
                        return log_error_errno(errno, "Failed to set CPU affinity: %m");

        r = drop_capabilities();
        if (r < 0)
                return log_error_errno(r, "drop_capabilities() failed: %m");

        (void) setup_hostname();

        if (arg_personality != PERSONALITY_INVALID) {
                r = safe_personality(arg_personality);
                if (r < 0)
                        return log_error_errno(r, "personality() failed: %m");
        } else if (secondary) {
                r = safe_personality(PER_LINUX32);
                if (r < 0)
                        return log_error_errno(r, "personality() failed: %m");
        }

#if HAVE_SELINUX
        if (arg_selinux_context)
                if (setexeccon(arg_selinux_context) < 0)
                        return log_error_errno(errno, "setexeccon(\"%s\") failed: %m", arg_selinux_context);
#endif

        r = change_uid_gid(arg_user, &home);
        if (r < 0)
                return r;

        if (arg_no_new_privileges)
                if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
                        return log_error_errno(errno, "Failed to disable new privileges: %m");

        /* LXC sets container=lxc, so follow the scheme here */
        envp[n_env++] = strjoina("container=", arg_container_service_name);

        envp[n_env] = strv_find_prefix(environ, "TERM=");
        if (envp[n_env])
                n_env++;

        if ((asprintf((char**)(envp + n_env++), "HOME=%s", home ? home: "/root") < 0) ||
            (asprintf((char**)(envp + n_env++), "USER=%s", arg_user ? arg_user : "root") < 0) ||
            (asprintf((char**)(envp + n_env++), "LOGNAME=%s", arg_user ? arg_user : "root") < 0))
                return log_oom();

        assert(!sd_id128_is_null(arg_uuid));

        if (asprintf((char**)(envp + n_env++), "container_uuid=%s", id128_to_uuid_string(arg_uuid, as_uuid)) < 0)
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
        if (!barrier_place_and_sync(barrier)) /* #5 */
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH),
                                       "Parent died too early");

        if (arg_chdir)
                if (chdir(arg_chdir) < 0)
                        return log_error_errno(errno, "Failed to change to specified working directory %s: %m", arg_chdir);

        if (arg_start_mode == START_PID2) {
                r = stub_pid1(arg_uuid);
                if (r < 0)
                        return r;
        }

        /* Now, explicitly close the log, so that we then can close all remaining fds. Closing the log explicitly first
         * has the benefit that the logging subsystem knows about it, and is thus ready to be reopened should we need
         * it again. Note that the other fds closed here are at least the locking and barrier fds. */
        log_close();
        log_set_open_when_needed(true);

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

                exec_target = "/usr/lib/systemd/systemd, /lib/systemd/systemd, /sbin/init";
        } else if (!strv_isempty(arg_parameters)) {
                const char *dollar_path;

                exec_target = arg_parameters[0];

                /* Use the user supplied search $PATH if there is one, or DEFAULT_PATH_COMPAT if not to search the
                 * binary. */
                dollar_path = strv_env_get(env_use, "PATH");
                if (dollar_path) {
                        if (putenv((char*) dollar_path) != 0)
                                return log_error_errno(errno, "Failed to update $PATH: %m");
                }

                execvpe(arg_parameters[0], arg_parameters, env_use);
        } else {
                if (!arg_chdir)
                        /* If we cannot change the directory, we'll end up in /, that is expected. */
                        (void) chdir(home ?: "/root");

                execle("/bin/bash", "-bash", NULL, env_use);
                execle("/bin/sh", "-sh", NULL, env_use);

                exec_target = "/bin/bash, /bin/sh";
        }

        return log_error_errno(errno, "execv(%s) failed: %m", exec_target);
}

static int setup_sd_notify_child(void) {
        _cleanup_close_ int fd = -1;
        union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = NSPAWN_NOTIFY_SOCKET_PATH,
        };
        int r;

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return log_error_errno(errno, "Failed to allocate notification socket: %m");

        (void) mkdir_parents(NSPAWN_NOTIFY_SOCKET_PATH, 0755);
        (void) sockaddr_un_unlink(&sa.un);

        r = bind(fd, &sa.sa, SOCKADDR_UN_LEN(sa.un));
        if (r < 0)
                return log_error_errno(errno, "bind(" NSPAWN_NOTIFY_SOCKET_PATH ") failed: %m");

        r = userns_lchown(NSPAWN_NOTIFY_SOCKET_PATH, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to chown " NSPAWN_NOTIFY_SOCKET_PATH ": %m");

        r = setsockopt_int(fd, SOL_SOCKET, SO_PASSCRED, true);
        if (r < 0)
                return log_error_errno(r, "SO_PASSCRED failed: %m");

        return TAKE_FD(fd);
}

static int outer_child(
                Barrier *barrier,
                const char *directory,
                const char *console,
                DissectedImage *dissected_image,
                bool interactive,
                bool secondary,
                int pid_socket,
                int uuid_socket,
                int notify_socket,
                int kmsg_socket,
                int rtnl_socket,
                int uid_shift_socket,
                int unified_cgroup_hierarchy_socket,
                FDSet *fds,
                int netns_fd) {

        _cleanup_close_ int fd = -1;
        int r, which_failed;
        pid_t pid;
        ssize_t l;

        /* This is the "outer" child process, i.e the one forked off by the container manager itself. It already has
         * its own CLONE_NEWNS namespace (which was created by the clone()). It still lives in the host's CLONE_NEWPID,
         * CLONE_NEWUTS, CLONE_NEWIPC, CLONE_NEWUSER and CLONE_NEWNET namespaces. After it completed a number of
         * initializations a second child (the "inner" one) is forked off it, and it exits. */

        assert(barrier);
        assert(directory);
        assert(console);
        assert(pid_socket >= 0);
        assert(uuid_socket >= 0);
        assert(notify_socket >= 0);
        assert(kmsg_socket >= 0);

        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
                return log_error_errno(errno, "PR_SET_PDEATHSIG failed: %m");

        if (interactive) {
                int terminal;

                terminal = open_terminal(console, O_RDWR);
                if (terminal < 0)
                        return log_error_errno(terminal, "Failed to open console: %m");

                /* Make sure we can continue logging to the original stderr, even if stderr points elsewhere now */
                r = log_dup_console();
                if (r < 0)
                        return log_error_errno(r, "Failed to duplicate stderr: %m");

                r = rearrange_stdio(terminal, terminal, terminal); /* invalidates 'terminal' on success and failure */
                if (r < 0)
                        return log_error_errno(r, "Failed to move console to stdin/stdout/stderr: %m");
        }

        r = reset_audit_loginuid();
        if (r < 0)
                return r;

        /* Mark everything as slave, so that we still
         * receive mounts from the real root, but don't
         * propagate mounts to the real root. */
        r = mount_verbose(LOG_ERR, NULL, "/", NULL, MS_SLAVE|MS_REC, NULL);
        if (r < 0)
                return r;

        if (dissected_image) {
                /* If we are operating on a disk image, then mount its root directory now, but leave out the rest. We
                 * can read the UID shift from it if we need to. Further down we'll mount the rest, but then with the
                 * uid shift known. That way we can mount VFAT file systems shifted to the right place right away. This
                 * makes sure ESP partitions and userns are compatible. */

                r = dissected_image_mount(dissected_image, directory, arg_uid_shift,
                                          DISSECT_IMAGE_MOUNT_ROOT_ONLY|DISSECT_IMAGE_DISCARD_ON_LOOP|
                                          (arg_read_only ? DISSECT_IMAGE_READ_ONLY : 0)|
                                          (arg_start_mode == START_BOOT ? DISSECT_IMAGE_VALIDATE_OS : 0));
                if (r < 0)
                        return r;
        }

        r = determine_uid_shift(directory);
        if (r < 0)
                return r;

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                /* Let the parent know which UID shift we read from the image */
                l = send(uid_shift_socket, &arg_uid_shift, sizeof(arg_uid_shift), MSG_NOSIGNAL);
                if (l < 0)
                        return log_error_errno(errno, "Failed to send UID shift: %m");
                if (l != sizeof(arg_uid_shift))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Short write while sending UID shift.");

                if (arg_userns_mode == USER_NAMESPACE_PICK) {
                        /* When we are supposed to pick the UID shift, the parent will check now whether the UID shift
                         * we just read from the image is available. If yes, it will send the UID shift back to us, if
                         * not it will pick a different one, and send it back to us. */

                        l = recv(uid_shift_socket, &arg_uid_shift, sizeof(arg_uid_shift), 0);
                        if (l < 0)
                                return log_error_errno(errno, "Failed to recv UID shift: %m");
                        if (l != sizeof(arg_uid_shift))
                                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                                       "Short read while receiving UID shift.");
                }

                log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                         "Selected user namespace base " UID_FMT " and range " UID_FMT ".", arg_uid_shift, arg_uid_range);
        }

        if (dissected_image) {
                /* Now we know the uid shift, let's now mount everything else that might be in the image. */
                r = dissected_image_mount(dissected_image, directory, arg_uid_shift,
                                          DISSECT_IMAGE_MOUNT_NON_ROOT_ONLY|DISSECT_IMAGE_DISCARD_ON_LOOP|(arg_read_only ? DISSECT_IMAGE_READ_ONLY : 0));
                if (r < 0)
                        return r;
        }

        if (arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_UNKNOWN) {
                /* OK, we don't know yet which cgroup mode to use yet. Let's figure it out, and tell the parent. */

                r = detect_unified_cgroup_hierarchy_from_image(directory);
                if (r < 0)
                        return r;

                l = send(unified_cgroup_hierarchy_socket, &arg_unified_cgroup_hierarchy, sizeof(arg_unified_cgroup_hierarchy), MSG_NOSIGNAL);
                if (l < 0)
                        return log_error_errno(errno, "Failed to send cgroup mode: %m");
                if (l != sizeof(arg_unified_cgroup_hierarchy))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Short write while sending cgroup mode.");

                unified_cgroup_hierarchy_socket = safe_close(unified_cgroup_hierarchy_socket);
        }

        /* Turn directory into bind mount */
        r = mount_verbose(LOG_ERR, directory, directory, NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                return r;

        r = setup_pivot_root(
                        directory,
                        arg_pivot_root_new,
                        arg_pivot_root_old);
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

        /* Mark everything as shared so our mounts get propagated down. This is
         * required to make new bind mounts available in systemd services
         * inside the containter that create a new mount namespace.
         * See https://github.com/systemd/systemd/issues/3860
         * Further submounts (such as /dev) done after this will inherit the
         * shared propagation mode. */
        r = mount_verbose(LOG_ERR, NULL, directory, NULL, MS_SHARED|MS_REC, NULL);
        if (r < 0)
                return r;

        r = recursive_chown(directory, arg_uid_shift, arg_uid_range);
        if (r < 0)
                return r;

        r = base_filesystem_create(directory, arg_uid_shift, (gid_t) arg_uid_shift);
        if (r < 0)
                return r;

        if (arg_read_only) {
                r = bind_remount_recursive(directory, true, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to make tree read-only: %m");
        }

        r = mount_all(directory,
                      arg_mount_settings,
                      arg_uid_shift,
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

        r = setup_keyring();
        if (r < 0)
                return r;

        r = setup_seccomp(arg_caps_retain, arg_syscall_whitelist, arg_syscall_blacklist);
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

        if (!arg_use_cgns) {
                r = mount_cgroups(
                                directory,
                                arg_unified_cgroup_hierarchy,
                                arg_userns_mode != USER_NAMESPACE_NO,
                                arg_uid_shift,
                                arg_uid_range,
                                arg_selinux_apifs_context,
                                false);
                if (r < 0)
                        return r;
        }

        r = mount_move_root(directory);
        if (r < 0)
                return log_error_errno(r, "Failed to move root directory: %m");

        fd = setup_sd_notify_child();
        if (fd < 0)
                return fd;

        r = setrlimit_closest_all((const struct rlimit *const*) arg_rlimit, &which_failed);
        if (r < 0)
                return log_error_errno(r, "Failed to apply resource limit RLIMIT_%s: %m", rlimit_to_string(which_failed));

        pid = raw_clone(SIGCHLD|CLONE_NEWNS|
                        arg_clone_ns_flags |
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

                if (arg_network_namespace_path) {
                        r = namespace_enter(-1, -1, netns_fd, -1, -1);
                        if (r < 0)
                                return log_error_errno(r, "Failed to join network namespace: %m");
                }

                r = inner_child(barrier, directory, secondary, kmsg_socket, rtnl_socket, fds);
                if (r < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        l = send(pid_socket, &pid, sizeof(pid), MSG_NOSIGNAL);
        if (l < 0)
                return log_error_errno(errno, "Failed to send PID: %m");
        if (l != sizeof(pid))
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Short write while sending PID.");

        l = send(uuid_socket, &arg_uuid, sizeof(arg_uuid), MSG_NOSIGNAL);
        if (l < 0)
                return log_error_errno(errno, "Failed to send machine ID: %m");
        if (l != sizeof(arg_uuid))
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Short write while sending machine ID.");

        l = send_one_fd(notify_socket, fd, 0);
        if (l < 0)
                return log_error_errno(errno, "Failed to send notify fd: %m");

        pid_socket = safe_close(pid_socket);
        uuid_socket = safe_close(uuid_socket);
        notify_socket = safe_close(notify_socket);
        kmsg_socket = safe_close(kmsg_socket);
        rtnl_socket = safe_close(rtnl_socket);
        netns_fd = safe_close(netns_fd);

        return 0;
}

static int uid_shift_pick(uid_t *shift, LockFile *ret_lock_file) {
        bool tried_hashed = false;
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
                char lock_path[STRLEN("/run/systemd/nspawn-uid/") + DECIMAL_STR_MAX(uid_t) + 1];
                _cleanup_(release_lock_file) LockFile lf = LOCK_FILE_INIT;

                if (--n_tries <= 0)
                        return -EBUSY;

                if (candidate < CONTAINER_UID_BASE_MIN || candidate > CONTAINER_UID_BASE_MAX)
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
                if (arg_machine && !tried_hashed) {
                        /* Try to hash the base from the container name */

                        static const uint8_t hash_key[] = {
                                0xe1, 0x56, 0xe0, 0xf0, 0x4a, 0xf0, 0x41, 0xaf,
                                0x96, 0x41, 0xcf, 0x41, 0x33, 0x94, 0xff, 0x72
                        };

                        candidate = (uid_t) siphash24(arg_machine, strlen(arg_machine), hash_key);

                        tried_hashed = true;
                } else
                        random_bytes(&candidate, sizeof(candidate));

                candidate = (candidate % (CONTAINER_UID_BASE_MAX - CONTAINER_UID_BASE_MIN)) + CONTAINER_UID_BASE_MIN;
                candidate &= (uid_t) UINT32_C(0xFFFF0000);
        }
}

static int setup_uid_map(pid_t pid) {
        char uid_map[STRLEN("/proc//uid_map") + DECIMAL_STR_MAX(uid_t) + 1], line[DECIMAL_STR_MAX(uid_t)*3+3+1];
        int r;

        assert(pid > 1);

        xsprintf(uid_map, "/proc/" PID_FMT "/uid_map", pid);
        xsprintf(line, UID_FMT " " UID_FMT " " UID_FMT "\n", 0, arg_uid_shift, arg_uid_range);
        r = write_string_file(uid_map, line, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write UID map: %m");

        /* We always assign the same UID and GID ranges */
        xsprintf(uid_map, "/proc/" PID_FMT "/gid_map", pid);
        r = write_string_file(uid_map, line, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write GID map: %m");

        return 0;
}

static int nspawn_dispatch_notify_fd(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
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
                if (IN_SET(errno, EAGAIN, EINTR))
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
                log_debug("Received notify message without valid credentials. Ignoring.");
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

static int setup_sd_notify_parent(sd_event *event, int fd, pid_t *inner_child_pid, sd_event_source **notify_event_source) {
        int r;

        r = sd_event_add_io(event, notify_event_source, fd, EPOLLIN, nspawn_dispatch_notify_fd, inner_child_pid);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate notify event source: %m");

        (void) sd_event_source_set_description(*notify_event_source, "nspawn-notify");

        return 0;
}

static int merge_settings(Settings *settings, const char *path) {
        int rl;

        assert(settings);
        assert(path);

        /* Copy over bits from the settings, unless they have been explicitly masked by command line switches. Note
         * that this steals the fields of the Settings* structure, and hence modifies it. */

        if ((arg_settings_mask & SETTING_START_MODE) == 0 &&
            settings->start_mode >= 0) {
                arg_start_mode = settings->start_mode;
                strv_free_and_replace(arg_parameters, settings->parameters);
        }

        if ((arg_settings_mask & SETTING_EPHEMERAL) == 0)
                arg_ephemeral = settings->ephemeral;

        if ((arg_settings_mask & SETTING_PIVOT_ROOT) == 0 &&
            settings->pivot_root_new) {
                free_and_replace(arg_pivot_root_new, settings->pivot_root_new);
                free_and_replace(arg_pivot_root_old, settings->pivot_root_old);
        }

        if ((arg_settings_mask & SETTING_WORKING_DIRECTORY) == 0 &&
            settings->working_directory)
                free_and_replace(arg_chdir, settings->working_directory);

        if ((arg_settings_mask & SETTING_ENVIRONMENT) == 0 &&
            settings->environment)
                strv_free_and_replace(arg_setenv, settings->environment);

        if ((arg_settings_mask & SETTING_USER) == 0 &&
            settings->user)
                free_and_replace(arg_user, settings->user);

        if ((arg_settings_mask & SETTING_CAPABILITY) == 0) {
                uint64_t plus;

                plus = settings->capability;
                if (settings_private_network(settings))
                        plus |= (1ULL << CAP_NET_ADMIN);

                if (!arg_settings_trusted && plus != 0) {
                        if (settings->capability != 0)
                                log_warning("Ignoring Capability= setting, file %s is not trusted.", path);
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
                        log_warning("Ignoring MachineID= setting, file %s is not trusted.", path);
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
                        log_warning("Ignoring TemporaryFileSystem=, Bind= and BindReadOnly= settings, file %s is not trusted.", path);
                else {
                        custom_mount_free_all(arg_custom_mounts, arg_n_custom_mounts);
                        arg_custom_mounts = TAKE_PTR(settings->custom_mounts);
                        arg_n_custom_mounts = settings->n_custom_mounts;
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
                        log_warning("Ignoring network settings, file %s is not trusted.", path);
                else {
                        arg_network_veth = settings_network_veth(settings);
                        arg_private_network = settings_private_network(settings);

                        strv_free_and_replace(arg_network_interfaces, settings->network_interfaces);
                        strv_free_and_replace(arg_network_macvlan, settings->network_macvlan);
                        strv_free_and_replace(arg_network_ipvlan, settings->network_ipvlan);
                        strv_free_and_replace(arg_network_veth_extra, settings->network_veth_extra);

                        free_and_replace(arg_network_bridge, settings->network_bridge);
                        free_and_replace(arg_network_zone, settings->network_zone);
                }
        }

        if ((arg_settings_mask & SETTING_EXPOSE_PORTS) == 0 &&
            settings->expose_ports) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring Port= setting, file %s is not trusted.", path);
                else {
                        expose_port_free_all(arg_expose_ports);
                        arg_expose_ports = TAKE_PTR(settings->expose_ports);
                }
        }

        if ((arg_settings_mask & SETTING_USERNS) == 0 &&
            settings->userns_mode != _USER_NAMESPACE_MODE_INVALID) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring PrivateUsers= and PrivateUsersChown= settings, file %s is not trusted.", path);
                else {
                        arg_userns_mode = settings->userns_mode;
                        arg_uid_shift = settings->uid_shift;
                        arg_uid_range = settings->uid_range;
                        arg_userns_chown = settings->userns_chown;
                }
        }

        if ((arg_settings_mask & SETTING_NOTIFY_READY) == 0)
                arg_notify_ready = settings->notify_ready;

        if ((arg_settings_mask & SETTING_SYSCALL_FILTER) == 0) {

                if (!arg_settings_trusted && !strv_isempty(arg_syscall_whitelist))
                        log_warning("Ignoring SystemCallFilter= settings, file %s is not trusted.", path);
                else {
                        strv_free_and_replace(arg_syscall_whitelist, settings->syscall_whitelist);
                        strv_free_and_replace(arg_syscall_blacklist, settings->syscall_blacklist);
                }
        }

        for (rl = 0; rl < _RLIMIT_MAX; rl ++) {
                if ((arg_settings_mask & (SETTING_RLIMIT_FIRST << rl)))
                        continue;

                if (!settings->rlimit[rl])
                        continue;

                if (!arg_settings_trusted) {
                        log_warning("Ignoring Limit%s= setting, file '%s' is not trusted.", rlimit_to_string(rl), path);
                        continue;
                }

                free_and_replace(arg_rlimit[rl], settings->rlimit[rl]);
        }

        if ((arg_settings_mask & SETTING_HOSTNAME) == 0 &&
            settings->hostname)
                free_and_replace(arg_hostname, settings->hostname);

        if ((arg_settings_mask & SETTING_NO_NEW_PRIVILEGES) == 0 &&
            settings->no_new_privileges >= 0)
                arg_no_new_privileges = settings->no_new_privileges;

        if ((arg_settings_mask & SETTING_OOM_SCORE_ADJUST) == 0 &&
            settings->oom_score_adjust_set) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring OOMScoreAdjust= setting, file '%s' is not trusted.", path);
                else {
                        arg_oom_score_adjust = settings->oom_score_adjust;
                        arg_oom_score_adjust_set = true;
                }
        }

        if ((arg_settings_mask & SETTING_CPU_AFFINITY) == 0 &&
            settings->cpuset) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring CPUAffinity= setting, file '%s' is not trusted.", path);
                else {
                        if (arg_cpuset)
                                CPU_FREE(arg_cpuset);
                        arg_cpuset = TAKE_PTR(settings->cpuset);
                        arg_cpuset_ncpus = settings->cpuset_ncpus;
                }
        }

        if ((arg_settings_mask & SETTING_RESOLV_CONF) == 0 &&
            settings->resolv_conf != _RESOLV_CONF_MODE_INVALID)
                arg_resolv_conf = settings->resolv_conf;

        if ((arg_settings_mask & SETTING_LINK_JOURNAL) == 0 &&
            settings->link_journal != _LINK_JOURNAL_INVALID) {

                if (!arg_settings_trusted)
                        log_warning("Ignoring journal link setting, file '%s' is not trusted.", path);
                else {
                        arg_link_journal = settings->link_journal;
                        arg_link_journal_try = settings->link_journal_try;
                }
        }

        if ((arg_settings_mask & SETTING_TIMEZONE) == 0 &&
            settings->timezone != _TIMEZONE_MODE_INVALID)
                arg_timezone = settings->timezone;

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

                j = strjoin(i, "/", fn);
                if (!j)
                        return log_oom();

                f = fopen(j, "re");
                if (f) {
                        p = TAKE_PTR(j);

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

        return merge_settings(settings, p);
}

static int run(int master,
               const char* console,
               DissectedImage *dissected_image,
               bool interactive,
               bool secondary,
               FDSet *fds,
               char veth_name[IFNAMSIZ], bool *veth_created,
               union in_addr_union *exposed,
               pid_t *pid, int *ret) {

        static const struct sigaction sa = {
                .sa_handler = nop_signal_handler,
                .sa_flags = SA_NOCLDSTOP|SA_RESTART,
        };

        _cleanup_(release_lock_file) LockFile uid_shift_lock = LOCK_FILE_INIT;
        _cleanup_close_ int etc_passwd_lock = -1;
        _cleanup_close_pair_ int
                kmsg_socket_pair[2] = { -1, -1 },
                rtnl_socket_pair[2] = { -1, -1 },
                pid_socket_pair[2] = { -1, -1 },
                uuid_socket_pair[2] = { -1, -1 },
                notify_socket_pair[2] = { -1, -1 },
                uid_shift_socket_pair[2] = { -1, -1 },
                unified_cgroup_hierarchy_socket_pair[2] = { -1, -1};

        _cleanup_close_ int notify_socket= -1;
        _cleanup_(barrier_destroy) Barrier barrier = BARRIER_NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *notify_event_source = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(pty_forward_freep) PTYForward *forward = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        ContainerStatus container_status = 0;
        char last_char = 0;
        int ifi = 0, r;
        ssize_t l;
        sigset_t mask_chld;
        _cleanup_close_ int netns_fd = -1;

        assert_se(sigemptyset(&mask_chld) == 0);
        assert_se(sigaddset(&mask_chld, SIGCHLD) == 0);

        if (arg_userns_mode == USER_NAMESPACE_PICK) {
                /* When we shall pick the UID/GID range, let's first lock /etc/passwd, so that we can safely
                 * check with getpwuid() if the specific user already exists. Note that /etc might be
                 * read-only, in which case this will fail with EROFS. But that's really OK, as in that case we
                 * can be reasonably sure that no users are going to be added. Note that getpwuid() checks are
                 * really just an extra safety net. We kinda assume that the UID range we allocate from is
                 * really ours. */

                etc_passwd_lock = take_etc_passwd_lock(NULL);
                if (etc_passwd_lock < 0 && etc_passwd_lock != -EROFS)
                        return log_error_errno(etc_passwd_lock, "Failed to take /etc/passwd lock: %m");
        }

        r = barrier_create(&barrier);
        if (r < 0)
                return log_error_errno(r, "Cannot initialize IPC barrier: %m");

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, kmsg_socket_pair) < 0)
                return log_error_errno(errno, "Failed to create kmsg socket pair: %m");

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, rtnl_socket_pair) < 0)
                return log_error_errno(errno, "Failed to create rtnl socket pair: %m");

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pid_socket_pair) < 0)
                return log_error_errno(errno, "Failed to create pid socket pair: %m");

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, uuid_socket_pair) < 0)
                return log_error_errno(errno, "Failed to create id socket pair: %m");

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, notify_socket_pair) < 0)
                return log_error_errno(errno, "Failed to create notify socket pair: %m");

        if (arg_userns_mode != USER_NAMESPACE_NO)
                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, uid_shift_socket_pair) < 0)
                        return log_error_errno(errno, "Failed to create uid shift socket pair: %m");

        if (arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_UNKNOWN)
                if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, unified_cgroup_hierarchy_socket_pair) < 0)
                        return log_error_errno(errno, "Failed to create unified cgroup socket pair: %m");

        /* Child can be killed before execv(), so handle SIGCHLD in order to interrupt
         * parent's blocking calls and give it a chance to call wait() and terminate. */
        r = sigprocmask(SIG_UNBLOCK, &mask_chld, NULL);
        if (r < 0)
                return log_error_errno(errno, "Failed to change the signal mask: %m");

        r = sigaction(SIGCHLD, &sa, NULL);
        if (r < 0)
                return log_error_errno(errno, "Failed to install SIGCHLD handler: %m");

        if (arg_network_namespace_path) {
                netns_fd = open(arg_network_namespace_path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (netns_fd < 0)
                        return log_error_errno(errno, "Cannot open file %s: %m", arg_network_namespace_path);

                r = fd_is_network_ns(netns_fd);
                if (r == -EUCLEAN)
                        log_debug_errno(r, "Cannot determine if passed network namespace path '%s' really refers to a network namespace, assuming it does.", arg_network_namespace_path);
                else if (r < 0)
                        return log_error_errno(r, "Failed to check %s fs type: %m", arg_network_namespace_path);
                else if (r == 0) {
                        log_error("Path %s doesn't refer to a network namespace, refusing.", arg_network_namespace_path);
                        return -EINVAL;
                }
        }

        *pid = raw_clone(SIGCHLD|CLONE_NEWNS);
        if (*pid < 0)
                return log_error_errno(errno, "clone() failed%s: %m",
                                       errno == EINVAL ?
                                       ", do you have namespace support enabled in your kernel? (You need UTS, IPC, PID and NET namespacing built in)" : "");

        if (*pid == 0) {
                /* The outer child only has a file system namespace. */
                barrier_set_role(&barrier, BARRIER_CHILD);

                master = safe_close(master);

                kmsg_socket_pair[0] = safe_close(kmsg_socket_pair[0]);
                rtnl_socket_pair[0] = safe_close(rtnl_socket_pair[0]);
                pid_socket_pair[0] = safe_close(pid_socket_pair[0]);
                uuid_socket_pair[0] = safe_close(uuid_socket_pair[0]);
                notify_socket_pair[0] = safe_close(notify_socket_pair[0]);
                uid_shift_socket_pair[0] = safe_close(uid_shift_socket_pair[0]);
                unified_cgroup_hierarchy_socket_pair[0] = safe_close(unified_cgroup_hierarchy_socket_pair[0]);

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                r = outer_child(&barrier,
                                arg_directory,
                                console,
                                dissected_image,
                                interactive,
                                secondary,
                                pid_socket_pair[1],
                                uuid_socket_pair[1],
                                notify_socket_pair[1],
                                kmsg_socket_pair[1],
                                rtnl_socket_pair[1],
                                uid_shift_socket_pair[1],
                                unified_cgroup_hierarchy_socket_pair[1],
                                fds,
                                netns_fd);
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
        unified_cgroup_hierarchy_socket_pair[1] = safe_close(unified_cgroup_hierarchy_socket_pair[1]);

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                /* The child just let us know the UID shift it might have read from the image. */
                l = recv(uid_shift_socket_pair[0], &arg_uid_shift, sizeof arg_uid_shift, 0);
                if (l < 0)
                        return log_error_errno(errno, "Failed to read UID shift: %m");
                if (l != sizeof arg_uid_shift) {
                        log_error("Short read while reading UID shift.");
                        return -EIO;
                }

                if (arg_userns_mode == USER_NAMESPACE_PICK) {
                        /* If we are supposed to pick the UID shift, let's try to use the shift read from the
                         * image, but if that's already in use, pick a new one, and report back to the child,
                         * which one we now picked. */

                        r = uid_shift_pick(&arg_uid_shift, &uid_shift_lock);
                        if (r < 0)
                                return log_error_errno(r, "Failed to pick suitable UID/GID range: %m");

                        l = send(uid_shift_socket_pair[0], &arg_uid_shift, sizeof arg_uid_shift, MSG_NOSIGNAL);
                        if (l < 0)
                                return log_error_errno(errno, "Failed to send UID shift: %m");
                        if (l != sizeof arg_uid_shift) {
                                log_error("Short write while writing UID shift.");
                                return -EIO;
                        }
                }
        }

        if (arg_unified_cgroup_hierarchy == CGROUP_UNIFIED_UNKNOWN) {
                /* The child let us know the support cgroup mode it might have read from the image. */
                l = recv(unified_cgroup_hierarchy_socket_pair[0], &arg_unified_cgroup_hierarchy, sizeof(arg_unified_cgroup_hierarchy), 0);
                if (l < 0)
                        return log_error_errno(errno, "Failed to read cgroup mode: %m");
                if (l != sizeof(arg_unified_cgroup_hierarchy)) {
                        log_error("Short read while reading cgroup mode (%zu bytes).%s",
                                  l, l == 0 ? " The child is most likely dead." : "");
                        return -EIO;
                }
        }

        /* Wait for the outer child. */
        r = wait_for_terminate_and_check("(sd-namespace)", *pid, WAIT_LOG_ABNORMAL);
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS)
                return -EIO;

        /* And now retrieve the PID of the inner child. */
        l = recv(pid_socket_pair[0], pid, sizeof *pid, 0);
        if (l < 0)
                return log_error_errno(errno, "Failed to read inner child PID: %m");
        if (l != sizeof *pid) {
                log_error("Short read while reading inner child PID.");
                return -EIO;
        }

        /* We also retrieve container UUID in case it was generated by outer child */
        l = recv(uuid_socket_pair[0], &arg_uuid, sizeof arg_uuid, 0);
        if (l < 0)
                return log_error_errno(errno, "Failed to read container machine ID: %m");
        if (l != sizeof(arg_uuid)) {
                log_error("Short read while reading container machined ID.");
                return -EIO;
        }

        /* We also retrieve the socket used for notifications generated by outer child */
        notify_socket = receive_one_fd(notify_socket_pair[0], 0);
        if (notify_socket < 0)
                return log_error_errno(notify_socket,
                                       "Failed to receive notification socket from the outer child: %m");

        log_debug("Init process invoked as PID "PID_FMT, *pid);

        if (arg_userns_mode != USER_NAMESPACE_NO) {
                if (!barrier_place_and_sync(&barrier)) { /* #1 */
                        log_error("Child died too early.");
                        return -ESRCH;
                }

                r = setup_uid_map(*pid);
                if (r < 0)
                        return r;

                (void) barrier_place(&barrier); /* #2 */
        }

        if (arg_private_network) {
                if (!arg_network_namespace_path) {
                        /* Wait until the child has unshared its network namespace. */
                        if (!barrier_place_and_sync(&barrier)) { /* #3 */
                                log_error("Child died too early");
                                return -ESRCH;
                        }
                }

                r = move_network_interfaces(*pid, arg_network_interfaces);
                if (r < 0)
                        return r;

                if (arg_network_veth) {
                        r = setup_veth(arg_machine, *pid, veth_name,
                                       arg_network_bridge || arg_network_zone);
                        if (r < 0)
                                return r;
                        else if (r > 0)
                                ifi = r;

                        if (arg_network_bridge) {
                                /* Add the interface to a bridge */
                                r = setup_bridge(veth_name, arg_network_bridge, false);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        ifi = r;
                        } else if (arg_network_zone) {
                                /* Add the interface to a bridge, possibly creating it */
                                r = setup_bridge(veth_name, arg_network_zone, true);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        ifi = r;
                        }
                }

                r = setup_veth_extra(arg_machine, *pid, arg_network_veth_extra);
                if (r < 0)
                        return r;

                /* We created the primary and extra veth links now; let's remember this, so that we know to
                   remove them later on. Note that we don't bother with removing veth links that were created
                   here when their setup failed half-way, because in that case the kernel should be able to
                   remove them on its own, since they cannot be referenced by anything yet. */
                *veth_created = true;

                r = setup_macvlan(arg_machine, *pid, arg_network_macvlan);
                if (r < 0)
                        return r;

                r = setup_ipvlan(arg_machine, *pid, arg_network_ipvlan);
                if (r < 0)
                        return r;
        }

        if (arg_register || !arg_keep_unit) {
                r = sd_bus_default_system(&bus);
                if (r < 0)
                        return log_error_errno(r, "Failed to open system bus: %m");

                r = sd_bus_set_close_on_exit(bus, false);
                if (r < 0)
                        return log_error_errno(r, "Failed to disable close-on-exit behaviour: %m");
        }

        if (!arg_keep_unit) {
                /* When a new scope is created for this container, then we'll be registered as its controller, in which
                 * case PID 1 will send us a friendly RequestStop signal, when it is asked to terminate the
                 * scope. Let's hook into that, and cleanly shut down the container, and print a friendly message. */

                r = sd_bus_match_signal_async(
                                bus,
                                NULL,
                                "org.freedesktop.systemd1",
                                NULL,
                                "org.freedesktop.systemd1.Scope",
                                "RequestStop",
                                on_request_stop, NULL, PID_TO_PTR(*pid));
                if (r < 0)
                        return log_error_errno(r, "Failed to request RequestStop match: %m");
        }

        if (arg_register) {
                r = register_machine(
                                bus,
                                arg_machine,
                                *pid,
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
                        return r;

        } else if (!arg_keep_unit) {
                r = allocate_scope(
                                bus,
                                arg_machine,
                                *pid,
                                arg_slice,
                                arg_custom_mounts, arg_n_custom_mounts,
                                arg_kill_signal,
                                arg_property);
                if (r < 0)
                        return r;

        } else if (arg_slice || arg_property)
                log_notice("Machine and scope registration turned off, --slice= and --property= settings will have no effect.");

        r = sync_cgroup(*pid, arg_unified_cgroup_hierarchy, arg_uid_shift);
        if (r < 0)
                return r;

        r = create_subcgroup(*pid, arg_keep_unit, arg_unified_cgroup_hierarchy);
        if (r < 0)
                return r;

        r = chown_cgroup(*pid, arg_unified_cgroup_hierarchy, arg_uid_shift);
        if (r < 0)
                return r;

        /* Notify the child that the parent is ready with all
         * its setup (including cgroup-ification), and that
         * the child can now hand over control to the code to
         * run inside the container. */
        (void) barrier_place(&barrier); /* #4 */

        /* Block SIGCHLD here, before notifying child.
         * process_pty() will handle it with the other signals. */
        assert_se(sigprocmask(SIG_BLOCK, &mask_chld, NULL) >= 0);

        /* Reset signal to default */
        r = default_signals(SIGCHLD, -1);
        if (r < 0)
                return log_error_errno(r, "Failed to reset SIGCHLD: %m");

        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to get default event source: %m");

        (void) sd_event_set_watchdog(event, true);

        if (bus) {
                r = sd_bus_attach_event(bus, event, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach bus to event loop: %m");
        }

        r = setup_sd_notify_parent(event, notify_socket, PID_TO_PTR(*pid), &notify_event_source);
        if (r < 0)
                return r;

        /* Let the child know that we are ready and wait that the child is completely ready now. */
        if (!barrier_place_and_sync(&barrier)) { /* #5 */
                log_error("Child died too early.");
                return -ESRCH;
        }

        /* At this point we have made use of the UID we picked, and thus nss-mymachines
         * will make them appear in getpwuid(), thus we can release the /etc/passwd lock. */
        etc_passwd_lock = safe_close(etc_passwd_lock);

        sd_notifyf(false,
                   "STATUS=Container running.\n"
                   "X_NSPAWN_LEADER_PID=" PID_FMT, *pid);
        if (!arg_notify_ready)
                (void) sd_notify(false, "READY=1\n");

        if (arg_kill_signal > 0) {
                /* Try to kill the init system on SIGINT or SIGTERM */
                (void) sd_event_add_signal(event, NULL, SIGINT, on_orderly_shutdown, PID_TO_PTR(*pid));
                (void) sd_event_add_signal(event, NULL, SIGTERM, on_orderly_shutdown, PID_TO_PTR(*pid));
        } else {
                /* Immediately exit */
                (void) sd_event_add_signal(event, NULL, SIGINT, NULL, NULL);
                (void) sd_event_add_signal(event, NULL, SIGTERM, NULL, NULL);
        }

        /* Exit when the child exits */
        (void) sd_event_add_signal(event, NULL, SIGCHLD, on_sigchld, PID_TO_PTR(*pid));

        if (arg_expose_ports) {
                r = expose_port_watch_rtnl(event, rtnl_socket_pair[0], on_address_change, exposed, &rtnl);
                if (r < 0)
                        return r;

                (void) expose_port_execute(rtnl, arg_expose_ports, exposed);
        }

        rtnl_socket_pair[0] = safe_close(rtnl_socket_pair[0]);

        r = pty_forward_new(event, master,
                            PTY_FORWARD_IGNORE_VHANGUP | (interactive ? 0 : PTY_FORWARD_READ_ONLY),
                            &forward);
        if (r < 0)
                return log_error_errno(r, "Failed to create PTY forwarder: %m");

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        pty_forward_get_last_char(forward, &last_char);

        forward = pty_forward_free(forward);

        if (!arg_quiet && last_char != '\n')
                putc('\n', stdout);

        /* Kill if it is not dead yet anyway */
        if (bus) {
                if (arg_register)
                        terminate_machine(bus, arg_machine);
                else if (!arg_keep_unit)
                        terminate_scope(bus, arg_machine);
        }

        /* Normally redundant, but better safe than sorry */
        (void) kill(*pid, SIGKILL);

        r = wait_for_container(*pid, &container_status);
        *pid = 0;

        if (r < 0)
                /* We failed to wait for the container, or the container exited abnormally. */
                return r;
        if (r > 0 || container_status == CONTAINER_TERMINATED) {
                /* r > 0 → The container exited with a non-zero status.
                 *         As a special case, we need to replace 133 with a different value,
                 *         because 133 is special-cased in the service file to reboot the container.
                 * otherwise → The container exited with zero status and a reboot was not requested.
                 */
                if (r == EXIT_FORCE_RESTART)
                        r = EXIT_FAILURE; /* replace 133 with the general failure code */
                *ret = r;
                return 0; /* finito */
        }

        /* CONTAINER_REBOOTED, loop again */

        if (arg_keep_unit) {
                /* Special handling if we are running as a service: instead of simply
                 * restarting the machine we want to restart the entire service, so let's
                 * inform systemd about this with the special exit code 133. The service
                 * file uses RestartForceExitStatus=133 so that this results in a full
                 * nspawn restart. This is necessary since we might have cgroup parameters
                 * set we want to have flushed out. */
                *ret = EXIT_FORCE_RESTART;
                return 0; /* finito */
        }

        expose_port_flush(arg_expose_ports, exposed);

        (void) remove_veth_links(veth_name, arg_network_veth_extra);
        *veth_created = false;
        return 1; /* loop again */
}

static int initialize_rlimits(void) {
        /* The default resource limits the kernel passes to PID 1, as per kernel 4.16. Let's pass our container payload
         * the same values as the kernel originally passed to PID 1, in order to minimize differences between host and
         * container execution environments. */

        static const struct rlimit kernel_defaults[_RLIMIT_MAX] = {
                [RLIMIT_AS]       = { RLIM_INFINITY, RLIM_INFINITY },
                [RLIMIT_CORE]     = { 0,             RLIM_INFINITY },
                [RLIMIT_CPU]      = { RLIM_INFINITY, RLIM_INFINITY },
                [RLIMIT_DATA]     = { RLIM_INFINITY, RLIM_INFINITY },
                [RLIMIT_FSIZE]    = { RLIM_INFINITY, RLIM_INFINITY },
                [RLIMIT_LOCKS]    = { RLIM_INFINITY, RLIM_INFINITY },
                [RLIMIT_MEMLOCK]  = { 65536,         65536         },
                [RLIMIT_MSGQUEUE] = { 819200,        819200        },
                [RLIMIT_NICE]     = { 0,             0             },
                [RLIMIT_NOFILE]   = { 1024,          4096          },
                [RLIMIT_RSS]      = { RLIM_INFINITY, RLIM_INFINITY },
                [RLIMIT_RTPRIO]   = { 0,             0             },
                [RLIMIT_RTTIME]   = { RLIM_INFINITY, RLIM_INFINITY },
                [RLIMIT_STACK]    = { 8388608,       RLIM_INFINITY },

                /* The kernel scales the default for RLIMIT_NPROC and RLIMIT_SIGPENDING based on the system's amount of
                 * RAM. To provide best compatibility we'll read these limits off PID 1 instead of hardcoding them
                 * here. This is safe as we know that PID 1 doesn't change these two limits and thus the original
                 * kernel's initialization should still be valid during runtime — at least if PID 1 is systemd. Note
                 * that PID 1 changes a number of other resource limits during early initialization which is why we
                 * don't read the other limits from PID 1 but prefer the static table above. */
        };

        int rl;

        for (rl = 0; rl < _RLIMIT_MAX; rl++) {
                /* Let's only fill in what the user hasn't explicitly configured anyway */
                if ((arg_settings_mask & (SETTING_RLIMIT_FIRST << rl)) == 0) {
                        const struct rlimit *v;
                        struct rlimit buffer;

                        if (IN_SET(rl, RLIMIT_NPROC, RLIMIT_SIGPENDING)) {
                                /* For these two let's read the limits off PID 1. See above for an explanation. */

                                if (prlimit(1, rl, NULL, &buffer) < 0)
                                        return log_error_errno(errno, "Failed to read resource limit RLIMIT_%s of PID 1: %m", rlimit_to_string(rl));

                                v = &buffer;
                        } else
                                v = kernel_defaults + rl;

                        arg_rlimit[rl] = newdup(struct rlimit, v, 1);
                        if (!arg_rlimit[rl])
                                return log_oom();
                }

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *k = NULL;

                        (void) rlimit_format(arg_rlimit[rl], &k);
                        log_debug("Setting RLIMIT_%s to %s.", rlimit_to_string(rl), k);
                }
        }

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_free_ char *console = NULL;
        _cleanup_close_ int master = -1;
        _cleanup_fdset_free_ FDSet *fds = NULL;
        int r, n_fd_passed, ret = EXIT_SUCCESS;
        char veth_name[IFNAMSIZ] = "";
        bool secondary = false, remove_directory = false, remove_image = false;
        pid_t pid = 0;
        union in_addr_union exposed = {};
        _cleanup_(release_lock_file) LockFile tree_global_lock = LOCK_FILE_INIT, tree_local_lock = LOCK_FILE_INIT;
        bool interactive, veth_created = false, remove_tmprootdir = false;
        char tmprootdir[] = "/tmp/nspawn-root-XXXXXX";
        _cleanup_(loop_device_unrefp) LoopDevice *loop = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;

        log_parse_environment();
        log_open();

        /* Make sure rename_process() in the stub init process can work */
        saved_argv = argv;
        saved_argc = argc;

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = must_be_root();
        if (r < 0)
                goto finish;

        r = initialize_rlimits();
        if (r < 0)
                goto finish;

        r = determine_names();
        if (r < 0)
                goto finish;

        r = load_settings();
        if (r < 0)
                goto finish;

        parse_environment();

        r = cg_unified_flush();
        if (r < 0) {
                log_error_errno(r, "Failed to determine whether the unified cgroups hierarchy is used: %m");
                goto finish;
        }

        r = verify_arguments();
        if (r < 0)
                goto finish;

        r = detect_unified_cgroup_hierarchy_from_environment();
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

        /* The "default" umask. This is appropriate for most file and directory
        * operations performed by nspawn, and is the umask that will be used for
        * the child. Functions like copy_devnodes() change the umask temporarily. */
        umask(0022);

        if (arg_directory) {
                assert(!arg_image);

                if (path_equal(arg_directory, "/") && !arg_ephemeral) {
                        log_error("Spawning container on root directory is not supported. Consider using --ephemeral.");
                        r = -EINVAL;
                        goto finish;
                }

                if (arg_ephemeral) {
                        _cleanup_free_ char *np = NULL;

                        r = chase_symlinks_and_update(&arg_directory, 0);
                        if (r < 0)
                                goto finish;

                        /* If the specified path is a mount point we
                         * generate the new snapshot immediately
                         * inside it under a random name. However if
                         * the specified is not a mount point we
                         * create the new snapshot in the parent
                         * directory, just next to it. */
                        r = path_is_mount_point(arg_directory, NULL, 0);
                        if (r < 0) {
                                log_error_errno(r, "Failed to determine whether directory %s is mount point: %m", arg_directory);
                                goto finish;
                        }
                        if (r > 0)
                                r = tempfn_random_child(arg_directory, "machine.", &np);
                        else
                                r = tempfn_random(arg_directory, "machine.", &np);
                        if (r < 0) {
                                log_error_errno(r, "Failed to generate name for directory snapshot: %m");
                                goto finish;
                        }

                        r = image_path_lock(np, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r < 0) {
                                log_error_errno(r, "Failed to lock %s: %m", np);
                                goto finish;
                        }

                        r = btrfs_subvol_snapshot(arg_directory, np,
                                                  (arg_read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) |
                                                  BTRFS_SNAPSHOT_FALLBACK_COPY |
                                                  BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                                  BTRFS_SNAPSHOT_RECURSIVE |
                                                  BTRFS_SNAPSHOT_QUOTA);
                        if (r < 0) {
                                log_error_errno(r, "Failed to create snapshot %s from %s: %m", np, arg_directory);
                                goto finish;
                        }

                        free_and_replace(arg_directory, np);

                        remove_directory = true;

                } else {
                        r = chase_symlinks_and_update(&arg_directory, arg_template ? CHASE_NONEXISTENT : 0);
                        if (r < 0)
                                goto finish;

                        r = image_path_lock(arg_directory, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r == -EBUSY) {
                                log_error_errno(r, "Directory tree %s is currently busy.", arg_directory);
                                goto finish;
                        }
                        if (r < 0) {
                                log_error_errno(r, "Failed to lock %s: %m", arg_directory);
                                goto finish;
                        }

                        if (arg_template) {
                                r = chase_symlinks_and_update(&arg_template, 0);
                                if (r < 0)
                                        goto finish;

                                r = btrfs_subvol_snapshot(arg_template, arg_directory,
                                                          (arg_read_only ? BTRFS_SNAPSHOT_READ_ONLY : 0) |
                                                          BTRFS_SNAPSHOT_FALLBACK_COPY |
                                                          BTRFS_SNAPSHOT_FALLBACK_DIRECTORY |
                                                          BTRFS_SNAPSHOT_FALLBACK_IMMUTABLE |
                                                          BTRFS_SNAPSHOT_RECURSIVE |
                                                          BTRFS_SNAPSHOT_QUOTA);
                                if (r == -EEXIST)
                                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                                 "Directory %s already exists, not populating from template %s.", arg_directory, arg_template);
                                else if (r < 0) {
                                        log_error_errno(r, "Couldn't create snapshot %s from %s: %m", arg_directory, arg_template);
                                        goto finish;
                                } else
                                        log_full(arg_quiet ? LOG_DEBUG : LOG_INFO,
                                                 "Populated %s from template %s.", arg_directory, arg_template);
                        }
                }

                if (arg_start_mode == START_BOOT) {
                        const char *p;

                        if (arg_pivot_root_new)
                                p = prefix_roota(arg_directory, arg_pivot_root_new);
                        else
                                p = arg_directory;

                        if (path_is_os_tree(p) <= 0) {
                                log_error("Directory %s doesn't look like an OS root directory (os-release file is missing). Refusing.", p);
                                r = -EINVAL;
                                goto finish;
                        }
                } else {
                        const char *p, *q;

                        if (arg_pivot_root_new)
                                p = prefix_roota(arg_directory, arg_pivot_root_new);
                        else
                                p = arg_directory;

                        q = strjoina(p, "/usr/");

                        if (laccess(q, F_OK) < 0) {
                                log_error("Directory %s doesn't look like it has an OS tree. Refusing.", p);
                                r = -EINVAL;
                                goto finish;
                        }
                }

        } else {
                assert(arg_image);
                assert(!arg_template);

                r = chase_symlinks_and_update(&arg_image, 0);
                if (r < 0)
                        goto finish;

                if (arg_ephemeral)  {
                        _cleanup_free_ char *np = NULL;

                        r = tempfn_random(arg_image, "machine.", &np);
                        if (r < 0) {
                                log_error_errno(r, "Failed to generate name for image snapshot: %m");
                                goto finish;
                        }

                        r = image_path_lock(np, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r < 0) {
                                r = log_error_errno(r, "Failed to create image lock: %m");
                                goto finish;
                        }

                        r = copy_file(arg_image, np, O_EXCL, arg_read_only ? 0400 : 0600, FS_NOCOW_FL, COPY_REFLINK);
                        if (r < 0) {
                                r = log_error_errno(r, "Failed to copy image file: %m");
                                goto finish;
                        }

                        free_and_replace(arg_image, np);

                        remove_image = true;
                } else {
                        r = image_path_lock(arg_image, (arg_read_only ? LOCK_SH : LOCK_EX) | LOCK_NB, &tree_global_lock, &tree_local_lock);
                        if (r == -EBUSY) {
                                r = log_error_errno(r, "Disk image %s is currently busy.", arg_image);
                                goto finish;
                        }
                        if (r < 0) {
                                r = log_error_errno(r, "Failed to create image lock: %m");
                                goto finish;
                        }

                        if (!arg_root_hash) {
                                r = root_hash_load(arg_image, &arg_root_hash, &arg_root_hash_size);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to load root hash file for %s: %m", arg_image);
                                        goto finish;
                                }
                        }
                }

                if (!mkdtemp(tmprootdir)) {
                        r = log_error_errno(errno, "Failed to create temporary directory: %m");
                        goto finish;
                }

                remove_tmprootdir = true;

                arg_directory = strdup(tmprootdir);
                if (!arg_directory) {
                        r = log_oom();
                        goto finish;
                }

                r = loop_device_make_by_path(arg_image, arg_read_only ? O_RDONLY : O_RDWR, &loop);
                if (r < 0) {
                        log_error_errno(r, "Failed to set up loopback block device: %m");
                        goto finish;
                }

                r = dissect_image_and_warn(
                                loop->fd,
                                arg_image,
                                arg_root_hash, arg_root_hash_size,
                                DISSECT_IMAGE_REQUIRE_ROOT,
                                &dissected_image);
                if (r == -ENOPKG) {
                        /* dissected_image_and_warn() already printed a brief error message. Extend on that with more details */
                        log_notice("Note that the disk image needs to\n"
                                   "    a) either contain only a single MBR partition of type 0x83 that is marked bootable\n"
                                   "    b) or contain a single GPT partition of type 0FC63DAF-8483-4772-8E79-3D69D8477DE4\n"
                                   "    c) or follow http://www.freedesktop.org/wiki/Specifications/DiscoverablePartitionsSpec/\n"
                                   "    d) or contain a file system without a partition table\n"
                                   "in order to be bootable with systemd-nspawn.");
                        goto finish;
                }
                if (r < 0)
                        goto finish;

                if (!arg_root_hash && dissected_image->can_verity)
                        log_notice("Note: image %s contains verity information, but no root hash specified! Proceeding without integrity checking.", arg_image);

                r = dissected_image_decrypt_interactively(dissected_image, NULL, arg_root_hash, arg_root_hash_size, 0, &decrypted_image);
                if (r < 0)
                        goto finish;

                /* Now that we mounted the image, let's try to remove it again, if it is ephemeral */
                if (remove_image && unlink(arg_image) >= 0)
                        remove_image = false;
        }

        r = custom_mount_prepare_all(arg_directory, arg_custom_mounts, arg_n_custom_mounts);
        if (r < 0)
                goto finish;

        interactive =
                isatty(STDIN_FILENO) > 0 &&
                isatty(STDOUT_FILENO) > 0;

        master = posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
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

        if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) < 0) {
                r = log_error_errno(errno, "Failed to become subreaper: %m");
                goto finish;
        }

        for (;;) {
                r = run(master,
                        console,
                        dissected_image,
                        interactive, secondary,
                        fds,
                        veth_name, &veth_created,
                        &exposed,
                        &pid, &ret);
                if (r <= 0)
                        break;
        }

finish:
        sd_notify(false,
                  r == 0 && ret == EXIT_FORCE_RESTART ? "STOPPING=1\nSTATUS=Restarting..." :
                                                        "STOPPING=1\nSTATUS=Terminating...");

        if (pid > 0)
                (void) kill(pid, SIGKILL);

        /* Try to flush whatever is still queued in the pty */
        if (master >= 0) {
                (void) copy_bytes(master, STDOUT_FILENO, (uint64_t) -1, 0);
                master = safe_close(master);
        }

        if (pid > 0)
                (void) wait_for_terminate(pid, NULL);

        pager_close();

        if (remove_directory && arg_directory) {
                int k;

                k = rm_rf(arg_directory, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                if (k < 0)
                        log_warning_errno(k, "Cannot remove '%s', ignoring: %m", arg_directory);
        }

        if (remove_image && arg_image) {
                if (unlink(arg_image) < 0)
                        log_warning_errno(errno, "Can't remove image file '%s', ignoring: %m", arg_image);
        }

        if (remove_tmprootdir) {
                if (rmdir(tmprootdir) < 0)
                        log_debug_errno(errno, "Can't remove temporary root directory '%s', ignoring: %m", tmprootdir);
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
        free(arg_hostname);
        free(arg_user);
        free(arg_pivot_root_new);
        free(arg_pivot_root_old);
        free(arg_chdir);
        strv_free(arg_setenv);
        free(arg_network_bridge);
        strv_free(arg_network_interfaces);
        strv_free(arg_network_macvlan);
        strv_free(arg_network_ipvlan);
        strv_free(arg_network_veth_extra);
        strv_free(arg_parameters);
        free(arg_network_zone);
        free(arg_network_namespace_path);
        strv_free(arg_property);
        custom_mount_free_all(arg_custom_mounts, arg_n_custom_mounts);
        expose_port_free_all(arg_expose_ports);
        free(arg_root_hash);
        rlimit_free_all(arg_rlimit);
        strv_free(arg_syscall_whitelist);
        strv_free(arg_syscall_blacklist);
        arg_cpuset = cpu_set_mfree(arg_cpuset);

        return r < 0 ? EXIT_FAILURE : ret;
}
