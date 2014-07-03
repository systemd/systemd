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
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <getopt.h>
#include <termios.h>
#include <sys/signalfd.h>
#include <grp.h>
#include <linux/fs.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/eventfd.h>
#include <net/if.h>
#include <linux/veth.h>
#include <sys/personality.h>
#include <linux/loop.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

#ifdef HAVE_BLKID
#include <blkid/blkid.h>
#endif

#include "sd-daemon.h"
#include "sd-bus.h"
#include "sd-id128.h"
#include "sd-rtnl.h"
#include "log.h"
#include "util.h"
#include "mkdir.h"
#include "macro.h"
#include "audit.h"
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
#include "bus-kernel.h"
#include "env-util.h"
#include "def.h"
#include "rtnl-util.h"
#include "udev-util.h"
#include "eventfd-util.h"
#include "blkid-util.h"
#include "gpt.h"
#include "siphash24.h"
#include "copy.h"
#include "base-filesystem.h"

#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#endif

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
static char *arg_user = NULL;
static sd_id128_t arg_uuid = {};
static char *arg_machine = NULL;
static const char *arg_selinux_context = NULL;
static const char *arg_selinux_apifs_context = NULL;
static const char *arg_slice = NULL;
static bool arg_private_network = false;
static bool arg_read_only = false;
static bool arg_boot = false;
static LinkJournal arg_link_journal = LINK_AUTO;
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
static bool arg_network_veth = false;
static const char *arg_network_bridge = NULL;
static unsigned long arg_personality = 0xffffffffLU;
static const char *arg_image = NULL;

static int help(void) {

        printf("%s [OPTIONS...] [PATH] [ARGUMENTS...]\n\n"
               "Spawn a minimal namespace container for debugging, testing and building.\n\n"
               "  -h --help                 Show this help\n"
               "     --version              Print version string\n"
               "  -q --quiet                Do not show status information\n"
               "  -D --directory=PATH       Root directory for the container\n"
               "  -i --image=PATH           File system device or image for the container\n"
               "  -b --boot                 Boot up full system (i.e. invoke init)\n"
               "  -u --user=USER            Run the command under specified user or uid\n"
               "  -M --machine=NAME         Set the machine name for the container\n"
               "     --uuid=UUID            Set a specific machine UUID for the container\n"
               "  -S --slice=SLICE          Place the container in the specified slice\n"
               "     --private-network      Disable network in container\n"
               "     --network-interface=INTERFACE\n"
               "                            Assign an existing network interface to the\n"
               "                            container\n"
               "     --network-macvlan=INTERFACE\n"
               "                            Create a macvlan network interface based on an\n"
               "                            existing network interface to the container\n"
               "     --network-veth         Add a virtual ethernet connection between host\n"
               "                            and container\n"
               "     --network-bridge=INTERFACE\n"
               "                            Add a virtual ethernet connection between host\n"
               "                            and container and add it to an existing bridge on\n"
               "                            the host\n"
               "  -Z --selinux-context=SECLABEL\n"
               "                            Set the SELinux security context to be used by\n"
               "                            processes in the container\n"
               "  -L --selinux-apifs-context=SECLABEL\n"
               "                            Set the SELinux security context to be used by\n"
               "                            API/tmpfs file systems in the container\n"
               "     --capability=CAP       In addition to the default, retain specified\n"
               "                            capability\n"
               "     --drop-capability=CAP  Drop the specified capability from the default set\n"
               "     --link-journal=MODE    Link up guest journal, one of no, auto, guest, host\n"
               "  -j                        Equivalent to --link-journal=host\n"
               "     --read-only            Mount the root directory read-only\n"
               "     --bind=PATH[:PATH]     Bind mount a file or directory from the host into\n"
               "                            the container\n"
               "     --bind-ro=PATH[:PATH]  Similar, but creates a read-only bind mount\n"
               "     --tmpfs=PATH:[OPTIONS] Mount an empty tmpfs to the specified directory\n"
               "     --setenv=NAME=VALUE    Pass an environment variable to PID 1\n"
               "     --share-system         Share system namespaces with host\n"
               "     --register=BOOLEAN     Register container as machine\n"
               "     --keep-unit            Do not register a scope for the machine, reuse\n"
               "                            the service unit nspawn is running in\n",
               program_invocation_short_name);

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
                ARG_NETWORK_VETH,
                ARG_NETWORK_BRIDGE,
                ARG_PERSONALITY,
        };

        static const struct option options[] = {
                { "help",                  no_argument,       NULL, 'h'                   },
                { "version",               no_argument,       NULL, ARG_VERSION           },
                { "directory",             required_argument, NULL, 'D'                   },
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
                { "network-veth",          no_argument,       NULL, ARG_NETWORK_VETH      },
                { "network-bridge",        required_argument, NULL, ARG_NETWORK_BRIDGE    },
                { "personality",           required_argument, NULL, ARG_PERSONALITY       },
                { "image",                 required_argument, NULL, 'i'                   },
                {}
        };

        int c, r;
        uint64_t plus = 0, minus = 0;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hD:u:bL:M:jS:Z:qi:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case 'D':
                        free(arg_directory);
                        arg_directory = canonicalize_file_name(optarg);
                        if (!arg_directory) {
                                log_error("Invalid root directory: %m");
                                return -ENOMEM;
                        }

                        break;

                case 'i':
                        arg_image = optarg;
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

                case ARG_NETWORK_VETH:
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

                                if (!hostname_is_valid(optarg)) {
                                        log_error("Invalid machine name: %s", optarg);
                                        return -EINVAL;
                                }

                                free(arg_machine);
                                arg_machine = strdup(optarg);
                                if (!arg_machine)
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
                        char *state, *word;
                        size_t length;

                        FOREACH_WORD_SEPARATOR(word, length, optarg, ",", state) {
                                _cleanup_free_ char *t;
                                cap_value_t cap;

                                t = strndup(word, length);
                                if (!t)
                                        return log_oom();

                                if (streq(t, "all")) {
                                        if (c == ARG_CAPABILITY)
                                                plus = (uint64_t) -1;
                                        else
                                                minus = (uint64_t) -1;
                                } else {
                                        if (cap_from_name(t, &cap) < 0) {
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
                        break;

                case ARG_LINK_JOURNAL:
                        if (streq(optarg, "auto"))
                                arg_link_journal = LINK_AUTO;
                        else if (streq(optarg, "no"))
                                arg_link_journal = LINK_NO;
                        else if (streq(optarg, "guest"))
                                arg_link_journal = LINK_GUEST;
                        else if (streq(optarg, "host"))
                                arg_link_journal = LINK_HOST;
                        else {
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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }
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

        arg_retain = (arg_retain | plus | (arg_private_network ? 1ULL << CAP_NET_ADMIN : 0)) & ~minus;

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
#ifdef HAVE_SELINUX
                { "/sys/fs/selinux", "/sys/fs/selinux", NULL, NULL, MS_BIND,                              false },  /* Bind mount first */
                { NULL,              "/sys/fs/selinux", NULL, NULL, MS_BIND|MS_RDONLY|MS_REMOUNT,         false },  /* Then, make it r/o */
#endif
        };

        unsigned k;
        int r = 0;

        for (k = 0; k < ELEMENTSOF(mount_table); k++) {
                _cleanup_free_ char *where = NULL;
#ifdef HAVE_SELINUX
                _cleanup_free_ char *options = NULL;
#endif
                const char *o;
                int t;

                where = strjoin(dest, "/", mount_table[k].where, NULL);
                if (!where)
                        return log_oom();

                t = path_is_mount_point(where, true);
                if (t < 0) {
                        log_error("Failed to detect whether %s is a mount point: %s", where, strerror(-t));

                        if (r == 0)
                                r = t;

                        continue;
                }

                /* Skip this entry if it is not a remount. */
                if (mount_table[k].what && t > 0)
                        continue;

                mkdir_p(where, 0755);

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


                if (mount(mount_table[k].what,
                          where,
                          mount_table[k].type,
                          mount_table[k].flags,
                          o) < 0 &&
                    mount_table[k].fatal) {

                        log_error("mount(%s) failed: %m", where);

                        if (r == 0)
                                r = -errno;
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

                if (stat(*x, &source_st) < 0) {
                        log_error("Failed to stat %s: %m", *x);
                        return -errno;
                }

                where = strappend(dest, *y);
                if (!where)
                        return log_oom();

                r = stat(where, &dest_st);
                if (r == 0) {
                        if ((source_st.st_mode & S_IFMT) != (dest_st.st_mode & S_IFMT)) {
                                log_error("The file types of %s and %s do not match. Refusing bind mount", *x, where);
                                return -EINVAL;
                        }
                } else if (errno == ENOENT) {
                        r = mkdir_parents_label(where, 0755);
                        if (r < 0) {
                                log_error("Failed to bind mount %s: %s", *x, strerror(-r));
                                return r;
                        }
                } else {
                        log_error("Failed to bind mount %s: %m", *x);
                        return -errno;
                }

                /* Create the mount point, but be conservative -- refuse to create block
                * and char devices. */
                if (S_ISDIR(source_st.st_mode))
                        mkdir_label(where, 0755);
                else if (S_ISFIFO(source_st.st_mode))
                        mkfifo(where, 0644);
                else if (S_ISSOCK(source_st.st_mode))
                        mknod(where, 0644 | S_IFSOCK, 0);
                else if (S_ISREG(source_st.st_mode))
                        touch(where);
                else {
                        log_error("Refusing to create mountpoint for file: %s", *x);
                        return -ENOTSUP;
                }

                if (mount(*x, where, "bind", MS_BIND, NULL) < 0) {
                        log_error("mount(%s) failed: %m", where);
                        return -errno;
                }

                if (ro) {
                        r = bind_remount_recursive(where, true);
                        if (r < 0) {
                                log_error("Read-Only bind mount failed: %s", strerror(-r));
                                return r;
                        }
                }
        }

        return 0;
}

static int mount_tmpfs(const char *dest) {
        char **i, **o;

        STRV_FOREACH_PAIR(i, o, arg_tmpfs) {
                _cleanup_free_ char *where = NULL;

                where = strappend(dest, *i);
                if (!where)
                        return log_oom();

                mkdir_label(where, 0755);

                if (mount("tmpfs", where, "tmpfs", MS_NODEV|MS_STRICTATIME, *o) < 0) {
                        log_error("tmpfs mount to %s failed: %m", where);
                        return -errno;
                }
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

        unlink(where);
        if (symlink(what, where) < 0) {
                log_error("Failed to correct timezone of container: %m");
                return 0;
        }

        return 0;
}

static int setup_resolv_conf(const char *dest) {
        _cleanup_free_ char *where = NULL;

        assert(dest);

        if (arg_private_network)
                return 0;

        /* Fix resolv.conf, if possible */
        where = strappend(dest, "/etc/resolv.conf");
        if (!where)
                return log_oom();

        /* We don't really care for the results of this really. If it
         * fails, it fails, but meh... */
        copy_file("/etc/resolv.conf", where, O_TRUNC|O_NOFOLLOW, 0644);

        return 0;
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
        if (r < 0) {
                log_error("Failed to generate random boot id: %s", strerror(-r));
                return r;
        }

        id128_format_as_uuid(rnd, as_uuid);

        r = write_string_file(from, as_uuid);
        if (r < 0) {
                log_error("Failed to write boot id: %s", strerror(-r));
                return r;
        }

        if (mount(from, to, "bind", MS_BIND, NULL) < 0) {
                log_error("Failed to bind mount boot id: %m");
                r = -errno;
        } else if (mount(from, to, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY, NULL))
                log_warning("Failed to make boot id read-only: %m");

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
                "tty\0";

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

                        if (errno != ENOENT) {
                                log_error("Failed to stat %s: %m", from);
                                return -errno;
                        }

                } else if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {

                        log_error("%s is not a char or block device, cannot copy", from);
                        return -EIO;

                } else if (mknod(to, st.st_mode, st.st_rdev) < 0) {

                        log_error("mknod(%s) failed: %m", dest);
                        return  -errno;
                }
        }

        return r;
}

static int setup_ptmx(const char *dest) {
        _cleanup_free_ char *p = NULL;

        p = strappend(dest, "/dev/ptmx");
        if (!p)
                return log_oom();

        if (symlink("pts/ptmx", p) < 0) {
                log_error("Failed to create /dev/ptmx symlink: %m");
                return -errno;
        }

        return 0;
}

static int setup_dev_console(const char *dest, const char *console) {
        _cleanup_umask_ mode_t u;
        const char *to;
        struct stat st;
        int r;

        assert(dest);
        assert(console);

        u = umask(0000);

        if (stat("/dev/null", &st) < 0) {
                log_error("Failed to stat /dev/null: %m");
                return -errno;
        }

        r = chmod_and_chown(console, 0600, 0, 0);
        if (r < 0) {
                log_error("Failed to correct access mode for TTY: %s", strerror(-r));
                return r;
        }

        /* We need to bind mount the right tty to /dev/console since
         * ptys can only exist on pts file systems. To have something
         * to bind mount things on we create a device node first, and
         * use /dev/null for that since we the cgroups device policy
         * allows us to create that freely, while we cannot create
         * /dev/console. (Note that the major minor doesn't actually
         * matter here, since we mount it over anyway). */

        to = strappenda(dest, "/dev/console");
        if (mknod(to, (st.st_mode & ~07777) | 0600, st.st_rdev) < 0) {
                log_error("mknod() for /dev/console failed: %m");
                return -errno;
        }

        if (mount(console, to, "bind", MS_BIND, NULL) < 0) {
                log_error("Bind mount for /dev/console failed: %m");
                return -errno;
        }

        return 0;
}

static int setup_kmsg(const char *dest, int kmsg_socket) {
        _cleanup_free_ char *from = NULL, *to = NULL;
        int r, fd, k;
        _cleanup_umask_ mode_t u;
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

        if (mkfifo(from, 0600) < 0) {
                log_error("mkfifo() for /dev/kmsg failed: %m");
                return -errno;
        }

        r = chmod_and_chown(from, 0600, 0, 0);
        if (r < 0) {
                log_error("Failed to correct access mode for /dev/kmsg: %s", strerror(-r));
                return r;
        }

        if (mount(from, to, "bind", MS_BIND, NULL) < 0) {
                log_error("Bind mount for /proc/kmsg failed: %m");
                return -errno;
        }

        fd = open(from, O_RDWR|O_NDELAY|O_CLOEXEC);
        if (fd < 0) {
                log_error("Failed to open fifo: %m");
                return -errno;
        }

        cmsg = CMSG_FIRSTHDR(&mh);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

        mh.msg_controllen = cmsg->cmsg_len;

        /* Store away the fd in the socket, so that it stays open as
         * long as we run the child */
        k = sendmsg(kmsg_socket, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        safe_close(fd);

        if (k < 0) {
                log_error("Failed to send FIFO fd: %m");
                return -errno;
        }

        /* And now make the FIFO unavailable as /dev/kmsg... */
        unlink(from);
        return 0;
}

static int setup_hostname(void) {

        if (arg_share_system)
                return 0;

        if (sethostname(arg_machine, strlen(arg_machine)) < 0)
                return -errno;

        return 0;
}

static int setup_journal(const char *directory) {
        sd_id128_t machine_id, this_id;
        _cleanup_free_ char *p = NULL, *b = NULL, *q = NULL, *d = NULL;
        char *id;
        int r;

        p = strappend(directory, "/etc/machine-id");
        if (!p)
                return log_oom();

        r = read_one_line_file(p, &b);
        if (r == -ENOENT && arg_link_journal == LINK_AUTO)
                return 0;
        else if (r < 0) {
                log_error("Failed to read machine ID from %s: %s", p, strerror(-r));
                return r;
        }

        id = strstrip(b);
        if (isempty(id) && arg_link_journal == LINK_AUTO)
                return 0;

        /* Verify validity */
        r = sd_id128_from_string(id, &machine_id);
        if (r < 0) {
                log_error("Failed to parse machine ID from %s: %s", p, strerror(-r));
                return r;
        }

        r = sd_id128_get_machine(&this_id);
        if (r < 0) {
                log_error("Failed to retrieve machine ID: %s", strerror(-r));
                return r;
        }

        if (sd_id128_equal(machine_id, this_id)) {
                log_full(arg_link_journal == LINK_AUTO ? LOG_WARNING : LOG_ERR,
                         "Host and machine ids are equal (%s): refusing to link journals", id);
                if (arg_link_journal == LINK_AUTO)
                        return 0;
                return
                        -EEXIST;
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
                                log_warning("failed to create directory %s: %m", q);
                        return 0;
                }

                if (unlink(p) < 0) {
                        log_error("Failed to remove symlink %s: %m", p);
                        return -errno;
                }
        } else if (r == -EINVAL) {

                if (arg_link_journal == LINK_GUEST &&
                    rmdir(p) < 0) {

                        if (errno == ENOTDIR) {
                                log_error("%s already exists and is neither a symlink nor a directory", p);
                                return r;
                        } else {
                                log_error("Failed to remove %s: %m", p);
                                return -errno;
                        }
                }
        } else if (r != -ENOENT) {
                log_error("readlink(%s) failed: %m", p);
                return r;
        }

        if (arg_link_journal == LINK_GUEST) {

                if (symlink(q, p) < 0) {
                        log_error("Failed to symlink %s to %s: %m", q, p);
                        return -errno;
                }

                r = mkdir_p(q, 0755);
                if (r < 0)
                        log_warning("failed to create directory %s: %m", q);
                return 0;
        }

        if (arg_link_journal == LINK_HOST) {
                r = mkdir_p(p, 0755);
                if (r < 0) {
                        log_error("Failed to create %s: %m", p);
                        return r;
                }

        } else if (access(p, F_OK) < 0)
                return 0;

        if (dir_is_empty(q) == 0)
                log_warning("%s is not empty, proceeding anyway.", q);

        r = mkdir_p(q, 0755);
        if (r < 0) {
                log_error("Failed to create %s: %m", q);
                return r;
        }

        if (mount(p, q, "bind", MS_BIND, NULL) < 0) {
                log_error("Failed to bind mount journal from host into guest: %m");
                return -errno;
        }

        return 0;
}

static int setup_kdbus(const char *dest, const char *path) {
        const char *p;

        if (!path)
                return 0;

        p = strappenda(dest, "/dev/kdbus");
        if (mkdir(p, 0755) < 0) {
                log_error("Failed to create kdbus path: %m");
                return  -errno;
        }

        if (mount(path, p, "bind", MS_BIND, NULL) < 0) {
                log_error("Failed to mount kdbus domain path: %m");
                return -errno;
        }

        return 0;
}

static int drop_capabilities(void) {
        return capability_bounding_set_drop(~arg_retain, false);
}

static int register_machine(pid_t pid) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        if (!arg_register)
                return 0;

        r = sd_bus_default_system(&bus);
        if (r < 0) {
                log_error("Failed to open system bus: %s", strerror(-r));
                return r;
        }

        if (arg_keep_unit) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "RegisterMachine",
                                &error,
                                NULL,
                                "sayssus",
                                arg_machine,
                                SD_BUS_MESSAGE_APPEND_ID128(arg_uuid),
                                "nspawn",
                                "container",
                                (uint32_t) pid,
                                strempty(arg_directory));
        } else {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

                r = sd_bus_message_new_method_call(
                                bus,
                                &m,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "CreateMachine");
                if (r < 0) {
                        log_error("Failed to create message: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_append(
                                m,
                                "sayssus",
                                arg_machine,
                                SD_BUS_MESSAGE_APPEND_ID128(arg_uuid),
                                "nspawn",
                                "container",
                                (uint32_t) pid,
                                strempty(arg_directory));
                if (r < 0) {
                        log_error("Failed to append message arguments: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_open_container(m, 'a', "(sv)");
                if (r < 0) {
                        log_error("Failed to open container: %s", strerror(-r));
                        return r;
                }

                if (!isempty(arg_slice)) {
                        r = sd_bus_message_append(m, "(sv)", "Slice", "s", arg_slice);
                        if (r < 0) {
                                log_error("Failed to append slice: %s", strerror(-r));
                                return r;
                        }
                }

                r = sd_bus_message_append(m, "(sv)", "DevicePolicy", "s", "strict");
                if (r < 0) {
                        log_error("Failed to add device policy: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_append(m, "(sv)", "DeviceAllow", "a(ss)", 10,
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
                                          /* Allow the container
                                           * access to ptys. However,
                                           * do not permit the
                                           * container to ever create
                                           * these device nodes. */
                                          "/dev/pts/ptmx", "rw",
                                          "char-pts", "rw",
                                          /* Allow the container
                                           * access to all kdbus
                                           * devices. Again, the
                                           * container cannot create
                                           * these nodes, only use
                                           * them. We use a pretty
                                           * open match here, so that
                                           * the kernel API can still
                                           * change. */
                                          "char-kdbus", "rw",
                                          "char-kdbus/*", "rw");
                if (r < 0) {
                        log_error("Failed to add device whitelist: %s", strerror(-r));
                        return r;
                }

                r = sd_bus_message_close_container(m);
                if (r < 0) {
                        log_error("Failed to close container: %s", strerror(-r));
                        return r;
                }

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
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        const char *path;
        int r;

        if (!arg_register)
                return 0;

        r = sd_bus_default_system(&bus);
        if (r < 0) {
                log_error("Failed to open system bus: %s", strerror(-r));
                return r;
        }

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
        if (r < 0) {
                log_error("Failed to read /proc/self/loginuid: %s", strerror(-r));
                return r;
        }

        /* Already reset? */
        if (streq(p, "4294967295"))
                return 0;

        r = write_string_file("/proc/self/loginuid", "4294967295");
        if (r < 0) {
                log_error("Failed to reset audit login UID. This probably means that your kernel is too\n"
                          "old and you have audit enabled. Note that the auditing subsystem is known to\n"
                          "be incompatible with containers on old kernels. Please make sure to upgrade\n"
                          "your kernel or to off auditing with 'audit=0' on the kernel command line before\n"
                          "using systemd-nspawn. Sleeping for 5s... (%s)\n", strerror(-r));

                sleep(5);
        }

        return 0;
}

#define HASH_KEY SD_ID128_MAKE(c3,c4,f9,19,b5,57,b2,1c,e6,cf,14,27,03,9c,ee,a2)

static int get_mac(struct ether_addr *mac) {
        int r;

        uint8_t result[8];
        size_t l, sz;
        uint8_t *v;

        l = strlen(arg_machine);
        sz = sizeof(sd_id128_t) + l;
        v = alloca(sz);

        /* fetch some persistent data unique to the host */
        r = sd_id128_get_machine((sd_id128_t*) v);
        if (r < 0)
                return r;

        /* combine with some data unique (on this host) to this
         * container instance */
        memcpy(v + sizeof(sd_id128_t), arg_machine, l);

        /* Let's hash the host machine ID plus the container name. We
         * use a fixed, but originally randomly created hash key here. */
        siphash24(result, v, sz, HASH_KEY.bytes);

        assert_cc(ETH_ALEN <= sizeof(result));
        memcpy(mac->ether_addr_octet, result, ETH_ALEN);

        /* see eth_random_addr in the kernel */
        mac->ether_addr_octet[0] &= 0xfe;        /* clear multicast bit */
        mac->ether_addr_octet[0] |= 0x02;        /* set local assignment bit (IEEE802) */

        return 0;
}

static int setup_veth(pid_t pid, char iface_name[IFNAMSIZ]) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        struct ether_addr mac;
        int r;

        if (!arg_private_network)
                return 0;

        if (!arg_network_veth)
                return 0;

        /* Use two different interface name prefixes depending whether
         * we are in bridge mode or not. */
        if (arg_network_bridge)
                memcpy(iface_name, "vb-", 3);
        else
                memcpy(iface_name, "ve-", 3);
        strncpy(iface_name+3, arg_machine, IFNAMSIZ - 3);

        r = get_mac(&mac);
        if (r < 0) {
                log_error("Failed to generate predictable MAC address for host0");
                return r;
        }

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0) {
                log_error("Failed to connect to netlink: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0) {
                log_error("Failed to allocate netlink message: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, iface_name);
        if (r < 0) {
                log_error("Failed to add netlink interface name: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
        if (r < 0) {
                log_error("Failed to open netlink container: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "veth");
        if (r < 0) {
                log_error("Failed to open netlink container: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container(m, VETH_INFO_PEER);
        if (r < 0) {
                log_error("Failed to open netlink container: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, "host0");
        if (r < 0) {
                log_error("Failed to add netlink interface name: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, &mac);
        if (r < 0) {
                log_error("Failed to add netlink MAC address: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(m, IFLA_NET_NS_PID, pid);
        if (r < 0) {
                log_error("Failed to add netlink namespace field: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(m);
        if (r < 0) {
                log_error("Failed to close netlink container: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(m);
        if (r < 0) {
                log_error("Failed to close netlink container: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(m);
        if (r < 0) {
                log_error("Failed to close netlink container: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call(rtnl, m, 0, NULL);
        if (r < 0) {
                log_error("Failed to add new veth interfaces: %s", strerror(-r));
                return r;
        }

        return 0;
}

static int setup_bridge(const char veth_name[]) {
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
        if (bridge <= 0) {
                log_error("Failed to resolve interface %s: %m", arg_network_bridge);
                return -errno;
        }

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0) {
                log_error("Failed to connect to netlink: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_new_link(rtnl, &m, RTM_SETLINK, 0);
        if (r < 0) {
                log_error("Failed to allocate netlink message: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_link_set_flags(m, IFF_UP, IFF_UP);
        if (r < 0) {
                log_error("Failed to set IFF_UP flag: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, veth_name);
        if (r < 0) {
                log_error("Failed to add netlink interface name field: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(m, IFLA_MASTER, bridge);
        if (r < 0) {
                log_error("Failed to add netlink master field: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call(rtnl, m, 0, NULL);
        if (r < 0) {
                log_error("Failed to add veth interface to bridge: %s", strerror(-r));
                return r;
        }

        return 0;
}

static int parse_interface(struct udev *udev, const char *name) {
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        char ifi_str[2 + DECIMAL_STR_MAX(int)];
        int ifi;

        ifi = (int) if_nametoindex(name);
        if (ifi <= 0) {
                log_error("Failed to resolve interface %s: %m", name);
                return -errno;
        }

        sprintf(ifi_str, "n%i", ifi);
        d = udev_device_new_from_device_id(udev, ifi_str);
        if (!d) {
                log_error("Failed to get udev device for interface %s: %m", name);
                return -errno;
        }

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
        if (r < 0) {
                log_error("Failed to connect to netlink: %s", strerror(-r));
                return r;
        }

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

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, ifi);
                if (r < 0) {
                        log_error("Failed to allocate netlink message: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_append_u32(m, IFLA_NET_NS_PID, pid);
                if (r < 0) {
                        log_error("Failed to append namespace PID to netlink message: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_call(rtnl, m, 0, NULL);
                if (r < 0) {
                        log_error("Failed to move interface %s to namespace: %s", *i, strerror(-r));
                        return r;
                }
        }

        return 0;
}

static int setup_macvlan(pid_t pid) {
        _cleanup_udev_unref_ struct udev *udev = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        char **i;
        int r;

        if (!arg_private_network)
                return 0;

        if (strv_isempty(arg_network_macvlan))
                return 0;

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0) {
                log_error("Failed to connect to netlink: %s", strerror(-r));
                return r;
        }

        udev = udev_new();
        if (!udev) {
                log_error("Failed to connect to udev.");
                return -ENOMEM;
        }

        STRV_FOREACH(i, arg_network_macvlan) {
                _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL;
                _cleanup_free_ char *n = NULL;
                int ifi;

                ifi = parse_interface(udev, *i);
                if (ifi < 0)
                        return ifi;

                r = sd_rtnl_message_new_link(rtnl, &m, RTM_NEWLINK, 0);
                if (r < 0) {
                        log_error("Failed to allocate netlink message: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_append_u32(m, IFLA_LINK, ifi);
                if (r < 0) {
                        log_error("Failed to add netlink interface index: %s", strerror(-r));
                        return r;
                }

                n = strappend("mv-", *i);
                if (!n)
                        return log_oom();

                strshorten(n, IFNAMSIZ-1);

                r = sd_rtnl_message_append_string(m, IFLA_IFNAME, n);
                if (r < 0) {
                        log_error("Failed to add netlink interface name: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_append_u32(m, IFLA_NET_NS_PID, pid);
                if (r < 0) {
                        log_error("Failed to add netlink namespace field: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
                if (r < 0) {
                        log_error("Failed to open netlink container: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA, "macvlan");
                if (r < 0) {
                        log_error("Failed to open netlink container: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_append_u32(m, IFLA_MACVLAN_MODE, MACVLAN_MODE_BRIDGE);
                if (r < 0) {
                        log_error("Failed to append macvlan mode: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_close_container(m);
                if (r < 0) {
                        log_error("Failed to close netlink container: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_message_close_container(m);
                if (r < 0) {
                        log_error("Failed to close netlink container: %s", strerror(-r));
                        return r;
                }

                r = sd_rtnl_call(rtnl, m, 0, NULL);
                if (r < 0) {
                        log_error("Failed to add new macvlan interfaces: %s", strerror(-r));
                        return r;
                }
        }

        return 0;
}

static int setup_seccomp(void) {

#ifdef HAVE_SECCOMP
        static const int blacklist[] = {
                SCMP_SYS(kexec_load),
                SCMP_SYS(open_by_handle_at),
                SCMP_SYS(init_module),
                SCMP_SYS(finit_module),
                SCMP_SYS(delete_module),
                SCMP_SYS(iopl),
                SCMP_SYS(ioperm),
                SCMP_SYS(swapon),
                SCMP_SYS(swapoff),
        };

        scmp_filter_ctx seccomp;
        unsigned i;
        int r;

        seccomp = seccomp_init(SCMP_ACT_ALLOW);
        if (!seccomp)
                return log_oom();

        r = seccomp_add_secondary_archs(seccomp);
        if (r < 0) {
                log_error("Failed to add secondary archs to seccomp filter: %s", strerror(-r));
                goto finish;
        }

        for (i = 0; i < ELEMENTSOF(blacklist); i++) {
                r = seccomp_rule_add(seccomp, SCMP_ACT_ERRNO(EPERM), blacklist[i], 0);
                if (r == -EFAULT)
                        continue; /* unknown syscall */
                if (r < 0) {
                        log_error("Failed to block syscall: %s", strerror(-r));
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
                log_error("Failed to add audit seccomp rule: %s", strerror(-r));
                goto finish;
        }

        r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
        if (r < 0) {
                log_error("Failed to unset NO_NEW_PRIVS: %s", strerror(-r));
                goto finish;
        }

        r = seccomp_load(seccomp);
        if (r < 0)
                log_error("Failed to install seccomp audit filter: %s", strerror(-r));

finish:
        seccomp_release(seccomp);
        return r;
#else
        return 0;
#endif

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

        fd = open(arg_image, O_CLOEXEC|(arg_read_only ? O_RDONLY : O_RDWR)|O_NONBLOCK|O_NOCTTY);
        if (fd < 0) {
                log_error("Failed to open %s: %m", arg_image);
                return -errno;
        }

        if (fstat(fd, &st) < 0) {
                log_error("Failed to stat %s: %m", arg_image);
                return -errno;
        }

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
                log_error("%s is not a regular file or block device: %m", arg_image);
                return -EINVAL;
        }

        control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (control < 0) {
                log_error("Failed to open /dev/loop-control: %m");
                return -errno;
        }

        nr = ioctl(control, LOOP_CTL_GET_FREE);
        if (nr < 0) {
                log_error("Failed to allocate loop device: %m");
                return -errno;
        }

        if (asprintf(&loopdev, "/dev/loop%i", nr) < 0)
                return log_oom();

        loop = open(loopdev, O_CLOEXEC|(arg_read_only ? O_RDONLY : O_RDWR)|O_NONBLOCK|O_NOCTTY);
        if (loop < 0) {
                log_error("Failed to open loop device %s: %m", loopdev);
                return -errno;
        }

        if (ioctl(loop, LOOP_SET_FD, fd) < 0) {
                log_error("Failed to set loopback file descriptor on %s: %m", loopdev);
                return -errno;
        }

        if (arg_read_only)
                info.lo_flags |= LO_FLAGS_READ_ONLY;

        if (ioctl(loop, LOOP_SET_STATUS64, &info) < 0) {
                log_error("Failed to set loopback settings on %s: %m", loopdev);
                return -errno;
        }

        *device_path = loopdev;
        loopdev = NULL;

        *loop_nr = nr;

        r = loop;
        loop = -1;

        return r;
}

static int dissect_image(
                int fd,
                char **root_device, bool *root_device_rw,
                char **home_device, bool *home_device_rw,
                char **srv_device, bool *srv_device_rw,
                bool *secondary) {

#ifdef HAVE_BLKID
        int home_nr = -1, root_nr = -1, secondary_root_nr = -1, srv_nr = -1;
        _cleanup_free_ char *home = NULL, *root = NULL, *secondary_root = NULL, *srv = NULL;
        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        _cleanup_blkid_free_probe_ blkid_probe b = NULL;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        struct udev_list_entry *first, *item;
        bool home_rw = true, root_rw = true, secondary_root_rw = true, srv_rw = true;
        const char *pttype = NULL;
        blkid_partlist pl;
        struct stat st;
        int r;

        assert(fd >= 0);
        assert(root_device);
        assert(home_device);
        assert(srv_device);
        assert(secondary);

        b = blkid_new_probe();
        if (!b)
                return log_oom();

        errno = 0;
        r = blkid_probe_set_device(b, fd, 0, 0);
        if (r != 0) {
                if (errno == 0)
                        return log_oom();

                log_error("Failed to set device on blkid probe: %m");
                return -errno;
        }

        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2 || r == 1) {
                log_error("Failed to identify any partition table on %s.\n"
                          "Note that the disk image needs to follow http://www.freedesktop.org/wiki/Specifications/DiscoverablePartitionsSpec/ to be supported by systemd-nspawn.", arg_image);
                return -EINVAL;
        } else if (r != 0) {
                if (errno == 0)
                        errno = EIO;
                log_error("Failed to probe: %m");
                return -errno;
        }

        blkid_probe_lookup_value(b, "PTTYPE", &pttype, NULL);
        if (!streq_ptr(pttype, "gpt")) {
                log_error("Image %s does not carry a GUID Partition Table.\n"
                          "Note that the disk image needs to follow http://www.freedesktop.org/wiki/Specifications/DiscoverablePartitionsSpec/ to be supported by systemd-nspawn.", arg_image);
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

        if (fstat(fd, &st) < 0) {
                log_error("Failed to stat block device: %m");
                return -errno;
        }

        d = udev_device_new_from_devnum(udev, 'b', st.st_rdev);
        if (!d)
                return log_oom();

        e = udev_enumerate_new(udev);
        if (!e)
                return log_oom();

        r = udev_enumerate_add_match_parent(e, d);
        if (r < 0)
                return log_oom();

        r = udev_enumerate_scan_devices(e);
        if (r < 0) {
                log_error("Failed to scan for partition devices of %s: %s", arg_image, strerror(-r));
                return r;
        }

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                _cleanup_udev_device_unref_ struct udev_device *q;
                const char *stype, *node;
                unsigned long long flags;
                sd_id128_t type_id;
                blkid_partition pp;
                dev_t qn;
                int nr;

                errno = 0;
                q = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                if (!q) {
                        if (!errno)
                                errno = ENOMEM;

                        log_error("Failed to get partition device of %s: %m", arg_image);
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
                if (flags & GPT_FLAG_NO_AUTO)
                        continue;

                nr = blkid_partition_get_partno(pp);
                if (nr < 0)
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

                        free(home);
                        home = strdup(node);
                        if (!home)
                                return log_oom();
                } else if (sd_id128_equal(type_id, GPT_SRV)) {

                        if (srv && nr >= srv_nr)
                                continue;

                        srv_nr = nr;
                        srv_rw = !(flags & GPT_FLAG_READ_ONLY);

                        free(srv);
                        srv = strdup(node);
                        if (!srv)
                                return log_oom();
                }
#ifdef GPT_ROOT_NATIVE
                else if (sd_id128_equal(type_id, GPT_ROOT_NATIVE)) {

                        if (root && nr >= root_nr)
                                continue;

                        root_nr = nr;
                        root_rw = !(flags & GPT_FLAG_READ_ONLY);

                        free(root);
                        root = strdup(node);
                        if (!root)
                                return log_oom();
                }
#endif
#ifdef GPT_ROOT_SECONDARY
                else if (sd_id128_equal(type_id, GPT_ROOT_SECONDARY)) {

                        if (secondary_root && nr >= secondary_root_nr)
                                continue;

                        secondary_root_nr = nr;
                        secondary_root_rw = !(flags & GPT_FLAG_READ_ONLY);


                        free(secondary_root);
                        secondary_root = strdup(node);
                        if (!secondary_root)
                                return log_oom();
                }
#endif
        }

        if (!root && !secondary_root) {
                log_error("Failed to identify root partition in disk image %s.\n"
                          "Note that the disk image needs to follow http://www.freedesktop.org/wiki/Specifications/DiscoverablePartitionsSpec/ to be supported by systemd-nspawn.", arg_image);
                return -EINVAL;
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
        return -ENOTSUP;
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
                p = strappenda(where, directory);
        else
                p = where;

        errno = 0;
        b = blkid_new_probe_from_filename(what);
        if (!b) {
                if (errno == 0)
                        return log_oom();
                log_error("Failed to allocate prober for %s: %m", what);
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
                log_error("Failed to probe %s: %m", what);
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
                return -ENOTSUP;
        }

        if (mount(what, p, fstype, MS_NODEV|(rw ? 0 : MS_RDONLY), NULL) < 0) {
                log_error("Failed to mount %s: %m", what);
                return -errno;
        }

        return 0;
#else
        log_error("--image= is not supported, compiled without blkid support.");
        return -ENOTSUP;
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
                if (r < 0) {
                        log_error("Failed to mount root directory: %s", strerror(-r));
                        return r;
                }
        }

        if (home_device) {
                r = mount_device(home_device, arg_directory, "/home", home_device_rw);
                if (r < 0) {
                        log_error("Failed to mount home directory: %s", strerror(-r));
                        return r;
                }
        }

        if (srv_device) {
                r = mount_device(srv_device, arg_directory, "/srv", srv_device_rw);
                if (r < 0) {
                        log_error("Failed to mount server data directory: %s", strerror(-r));
                        return r;
                }
        }

        return 0;
}

static void loop_remove(int nr, int *image_fd) {
        _cleanup_close_ int control = -1;

        if (nr < 0)
                return;

        if (image_fd && *image_fd >= 0) {
                ioctl(*image_fd, LOOP_CLR_FD);
                *image_fd = safe_close(*image_fd);
        }

        control = open("/dev/loop-control", O_RDWR|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);
        if (control < 0)
                return;

        ioctl(control, LOOP_CTL_REMOVE, nr);
}

static int spawn_getent(const char *database, const char *key, pid_t *rpid) {
        int pipe_fds[2];
        pid_t pid;

        assert(database);
        assert(key);
        assert(rpid);

        if (pipe2(pipe_fds, O_CLOEXEC) < 0) {
                log_error("Failed to allocate pipe: %m");
                return -errno;
        }

        pid = fork();
        if (pid < 0) {
                log_error("Failed to fork getent child: %m");
                return -errno;
        } else if (pid == 0) {
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
        char line[LINE_MAX], *w, *x, *state, *u, *g, *h;
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

                if (setgroups(0, NULL) < 0) {
                        log_error("setgroups() failed: %m");
                        return -errno;
                }

                if (setresgid(0, 0, 0) < 0) {
                        log_error("setregid() failed: %m");
                        return -errno;
                }

                if (setresuid(0, 0, 0) < 0) {
                        log_error("setreuid() failed: %m");
                        return -errno;
                }

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

                log_error("Failed to read from getent: %m");
                return -errno;
        }

        truncate_nl(line);

        wait_for_terminate_and_warn("getent passwd", pid);

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

                log_error("Failed to read from getent: %m");
                return -errno;
        }

        truncate_nl(line);

        wait_for_terminate_and_warn("getent initgroups", pid);

        /* Skip over the username and subsequent separator whitespace */
        x = line;
        x += strcspn(x, WHITESPACE);
        x += strspn(x, WHITESPACE);

        FOREACH_WORD(w, l, x, state) {
                char c[l+1];

                memcpy(c, w, l);
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
        if (r < 0) {
                log_error("Failed to make home root directory: %s", strerror(-r));
                return r;
        }

        r = mkdir_safe(home, 0755, uid, gid);
        if (r < 0 && r != -EEXIST) {
                log_error("Failed to make home directory: %s", strerror(-r));
                return r;
        }

        fchown(STDIN_FILENO, uid, gid);
        fchown(STDOUT_FILENO, uid, gid);
        fchown(STDERR_FILENO, uid, gid);

        if (setgroups(n_uids, uids) < 0) {
                log_error("Failed to set auxiliary groups: %m");
                return -errno;
        }

        if (setresgid(gid, gid, gid) < 0) {
                log_error("setregid() failed: %m");
                return -errno;
        }

        if (setresuid(uid, uid, uid) < 0) {
                log_error("setreuid() failed: %m");
                return -errno;
        }

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
 *       container is returned.  No change is made to the container
 *       argument.
 *   0 : The container is being rebooted, has been shut down or exited
 *       successfully.  The container argument has been set to either
 *       CONTAINER_TERMINATED or CONTAINER_REBOOTED.
 *
 * That is, success is indicated by a return value of zero, and an
 * error is indicated by a non-zero value.
 */
static int wait_for_container(pid_t pid, ContainerStatus *container) {
        int r;
        siginfo_t status;

        r = wait_for_terminate(pid, &status);
        if (r < 0) {
                log_warning("Failed to wait for container: %s", strerror(-r));
                return r;
        }

        switch (status.si_code) {
        case CLD_EXITED:
                r = status.si_status;
                if (r == 0) {
                        if (!arg_quiet)
                                log_debug("Container %s exited successfully.",
                                          arg_machine);

                        *container = CONTAINER_TERMINATED;
                } else {
                        log_error("Container %s failed with error code %i.",
                                  arg_machine, status.si_status);
                }
                break;

        case CLD_KILLED:
                if (status.si_status == SIGINT) {
                        if (!arg_quiet)
                                log_info("Container %s has been shut down.",
                                         arg_machine);

                        *container = CONTAINER_TERMINATED;
                        r = 0;
                        break;
                } else if (status.si_status == SIGHUP) {
                        if (!arg_quiet)
                                log_info("Container %s is being rebooted.",
                                         arg_machine);

                        *container = CONTAINER_REBOOTED;
                        r = 0;
                        break;
                }
                /* CLD_KILLED fallthrough */

        case CLD_DUMPED:
                log_error("Container %s terminated by signal %s.",
                          arg_machine, signal_to_string(status.si_status));
                r = -1;
                break;

        default:
                log_error("Container %s failed due to unknown reason.",
                          arg_machine);
                r = -1;
                break;
        }

        return r;
}

static void nop_handler(int sig) {}

int main(int argc, char *argv[]) {

        _cleanup_free_ char *kdbus_domain = NULL, *device_path = NULL, *root_device = NULL, *home_device = NULL, *srv_device = NULL;
        bool root_device_rw = true, home_device_rw = true, srv_device_rw = true;
        _cleanup_close_ int master = -1, kdbus_fd = -1, image_fd = -1;
        _cleanup_close_pair_ int kmsg_socket_pair[2] = { -1, -1 };
        _cleanup_fdset_free_ FDSet *fds = NULL;
        int r = EXIT_FAILURE, k, n_fd_passed, loop_nr = -1;
        const char *console = NULL;
        char veth_name[IFNAMSIZ];
        bool secondary = false;
        sigset_t mask, mask_chld;
        pid_t pid = 0;

        log_parse_environment();
        log_open();

        k = parse_argv(argc, argv);
        if (k < 0)
                goto finish;
        else if (k == 0) {
                r = EXIT_SUCCESS;
                goto finish;
        }

        if (!arg_image) {
                if (arg_directory) {
                        char *p;

                        p = path_make_absolute_cwd(arg_directory);
                        free(arg_directory);
                        arg_directory = p;
                } else
                        arg_directory = get_current_dir_name();

                if (!arg_directory) {
                        log_error("Failed to determine path, please use -D.");
                        goto finish;
                }
                path_kill_slashes(arg_directory);
        }

        if (!arg_machine) {
                arg_machine = strdup(basename(arg_image ? arg_image : arg_directory));
                if (!arg_machine) {
                        log_oom();
                        goto finish;
                }

                hostname_cleanup(arg_machine, false);
                if (isempty(arg_machine)) {
                        log_error("Failed to determine machine name automatically, please use -M.");
                        goto finish;
                }
        }

        if (geteuid() != 0) {
                log_error("Need to be root.");
                goto finish;
        }

        if (sd_booted() <= 0) {
                log_error("Not running on a systemd system.");
                goto finish;
        }

        log_close();
        n_fd_passed = sd_listen_fds(false);
        if (n_fd_passed > 0) {
                k = fdset_new_listen_fds(&fds, false);
                if (k < 0) {
                        log_error("Failed to collect file descriptors: %s", strerror(-k));
                        goto finish;
                }
        }
        fdset_close_others(fds);
        log_open();

        if (arg_directory) {
                if (path_equal(arg_directory, "/")) {
                        log_error("Spawning container on root directory not supported.");
                        goto finish;
                }

                if (arg_boot) {
                        if (path_is_os_tree(arg_directory) <= 0) {
                                log_error("Directory %s doesn't look like an OS root directory (os-release file is missing). Refusing.", arg_directory);
                                goto finish;
                        }
                } else {
                        const char *p;

                        p = strappenda(arg_directory,
                                       argc > optind && path_is_absolute(argv[optind]) ? argv[optind] : "/usr/bin/");
                        if (access(p, F_OK) < 0) {
                                log_error("Directory %s lacks the binary to execute or doesn't look like a binary tree. Refusing.", arg_directory);
                                goto finish;

                        }
                }
        } else {
                char template[] = "/tmp/nspawn-root-XXXXXX";

                if (!mkdtemp(template)) {
                        log_error("Failed to create temporary directory: %m");
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

                r = dissect_image(image_fd, &root_device, &root_device_rw, &home_device, &home_device_rw, &srv_device, &srv_device_rw, &secondary);
                if (r < 0)
                        goto finish;
        }

        master = posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NDELAY);
        if (master < 0) {
                log_error("Failed to acquire pseudo tty: %m");
                goto finish;
        }

        console = ptsname(master);
        if (!console) {
                log_error("Failed to determine tty name: %m");
                goto finish;
        }

        if (!arg_quiet)
                log_info("Spawning container %s on %s.\nPress ^] three times within 1s to kill container.",
                         arg_machine, arg_image ? arg_image : arg_directory);

        if (unlockpt(master) < 0) {
                log_error("Failed to unlock tty: %m");
                goto finish;
        }

        if (access("/dev/kdbus/control", F_OK) >= 0) {

                if (arg_share_system) {
                        kdbus_domain = strdup("/dev/kdbus");
                        if (!kdbus_domain) {
                                log_oom();
                                goto finish;
                        }
                } else {
                        const char *ns;

                        ns = strappenda("machine-", arg_machine);
                        kdbus_fd = bus_kernel_create_domain(ns, &kdbus_domain);
                        if (r < 0)
                                log_debug("Failed to create kdbus domain: %s", strerror(-r));
                        else
                                log_debug("Successfully created kdbus domain as %s", kdbus_domain);
                }
        }

        if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, kmsg_socket_pair) < 0) {
                log_error("Failed to create kmsg socket pair: %m");
                goto finish;
        }

        sd_notify(0, "READY=1");

        assert_se(sigemptyset(&mask) == 0);
        assert_se(sigemptyset(&mask_chld) == 0);
        sigaddset(&mask_chld, SIGCHLD);
        sigset_add_many(&mask, SIGCHLD, SIGWINCH, SIGTERM, SIGINT, -1);
        assert_se(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);

        for (;;) {
                ContainerStatus container_status;
                int eventfds[2] = { -1, -1 };
                struct sigaction sa = {
                        .sa_handler = nop_handler,
                        .sa_flags = SA_NOCLDSTOP,
                };

                /* Child can be killed before execv(), so handle SIGCHLD
                 * in order to interrupt parent's blocking calls and
                 * give it a chance to call wait() and terminate. */
                r = sigprocmask(SIG_UNBLOCK, &mask_chld, NULL);
                if (r < 0) {
                        log_error("Failed to change the signal mask: %m");
                        goto finish;
                }

                r = sigaction(SIGCHLD, &sa, NULL);
                if (r < 0) {
                        log_error("Failed to install SIGCHLD handler: %m");
                        goto finish;
                }

                pid = clone_with_eventfd(SIGCHLD|CLONE_NEWNS|
                                         (arg_share_system ? 0 : CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWUTS)|
                                         (arg_private_network ? CLONE_NEWNET : 0), eventfds);
                if (pid < 0) {
                        if (errno == EINVAL)
                                log_error("clone() failed, do you have namespace support enabled in your kernel? (You need UTS, IPC, PID and NET namespacing built in): %m");
                        else
                                log_error("clone() failed: %m");

                        r = pid;
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

                        envp[n_env] = strv_find_prefix(environ, "TERM=");
                        if (envp[n_env])
                                n_env ++;

                        master = safe_close(master);

                        close_nointr(STDIN_FILENO);
                        close_nointr(STDOUT_FILENO);
                        close_nointr(STDERR_FILENO);

                        kmsg_socket_pair[0] = safe_close(kmsg_socket_pair[0]);

                        reset_all_signal_handlers();

                        assert_se(sigemptyset(&mask) == 0);
                        assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

                        k = open_terminal(console, O_RDWR);
                        if (k != STDIN_FILENO) {
                                if (k >= 0) {
                                        safe_close(k);
                                        k = -EINVAL;
                                }

                                log_error("Failed to open console: %s", strerror(-k));
                                goto child_fail;
                        }

                        if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO ||
                            dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) {
                                log_error("Failed to duplicate console: %m");
                                goto child_fail;
                        }

                        if (setsid() < 0) {
                                log_error("setsid() failed: %m");
                                goto child_fail;
                        }

                        if (reset_audit_loginuid() < 0)
                                goto child_fail;

                        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) {
                                log_error("PR_SET_PDEATHSIG failed: %m");
                                goto child_fail;
                        }

                        /* Mark everything as slave, so that we still
                         * receive mounts from the real root, but don't
                         * propagate mounts to the real root. */
                        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
                                log_error("MS_SLAVE|MS_REC failed: %m");
                                goto child_fail;
                        }

                        if (mount_devices(arg_directory,
                                          root_device, root_device_rw,
                                          home_device, home_device_rw,
                                          srv_device, srv_device_rw) < 0)
                                goto child_fail;

                        r = base_filesystem_create(arg_directory);
                        if (r < 0) {
                                log_error("Failed to create the base filesystem: %s", strerror(-r));
                                goto child_fail;
                        }

                        /* Turn directory into bind mount */
                        if (mount(arg_directory, arg_directory, "bind", MS_BIND|MS_REC, NULL) < 0) {
                                log_error("Failed to make bind mount: %m");
                                goto child_fail;
                        }

                        if (arg_read_only) {
                                k = bind_remount_recursive(arg_directory, true);
                                if (k < 0) {
                                        log_error("Failed to make tree read-only: %s", strerror(-k));
                                        goto child_fail;
                                }
                        }

                        if (mount_all(arg_directory) < 0)
                                goto child_fail;

                        if (copy_devnodes(arg_directory) < 0)
                                goto child_fail;

                        if (setup_ptmx(arg_directory) < 0)
                                goto child_fail;

                        dev_setup(arg_directory);

                        if (setup_seccomp() < 0)
                                goto child_fail;

                        if (setup_dev_console(arg_directory, console) < 0)
                                goto child_fail;

                        if (setup_kmsg(arg_directory, kmsg_socket_pair[1]) < 0)
                                goto child_fail;

                        kmsg_socket_pair[1] = safe_close(kmsg_socket_pair[1]);

                        if (setup_boot_id(arg_directory) < 0)
                                goto child_fail;

                        if (setup_timezone(arg_directory) < 0)
                                goto child_fail;

                        if (setup_resolv_conf(arg_directory) < 0)
                                goto child_fail;

                        if (setup_journal(arg_directory) < 0)
                                goto child_fail;

                        if (mount_binds(arg_directory, arg_bind, false) < 0)
                                goto child_fail;

                        if (mount_binds(arg_directory, arg_bind_ro, true) < 0)
                                goto child_fail;

                        if (mount_tmpfs(arg_directory) < 0)
                                goto child_fail;

                        if (setup_kdbus(arg_directory, kdbus_domain) < 0)
                                goto child_fail;

                        /* Tell the parent that we are ready, and that
                         * it can cgroupify us to that we lack access
                         * to certain devices and resources. */
                        r = eventfd_send_state(eventfds[1],
                                               EVENTFD_CHILD_SUCCEEDED);
                        eventfds[1] = safe_close(eventfds[1]);
                        if (r < 0)
                                goto child_fail;

                        if (chdir(arg_directory) < 0) {
                                log_error("chdir(%s) failed: %m", arg_directory);
                                goto child_fail;
                        }

                        if (mount(arg_directory, "/", NULL, MS_MOVE, NULL) < 0) {
                                log_error("mount(MS_MOVE) failed: %m");
                                goto child_fail;
                        }

                        if (chroot(".") < 0) {
                                log_error("chroot() failed: %m");
                                goto child_fail;
                        }

                        if (chdir("/") < 0) {
                                log_error("chdir() failed: %m");
                                goto child_fail;
                        }

                        umask(0022);

                        if (arg_private_network)
                                loopback_setup();

                        if (drop_capabilities() < 0) {
                                log_error("drop_capabilities() failed: %m");
                                goto child_fail;
                        }

                        r = change_uid_gid(&home);
                        if (r < 0)
                                goto child_fail;

                        if ((asprintf((char**)(envp + n_env++), "HOME=%s", home ? home: "/root") < 0) ||
                            (asprintf((char**)(envp + n_env++), "USER=%s", arg_user ? arg_user : "root") < 0) ||
                            (asprintf((char**)(envp + n_env++), "LOGNAME=%s", arg_user ? arg_user : "root") < 0)) {
                                log_oom();
                                goto child_fail;
                        }

                        if (!sd_id128_equal(arg_uuid, SD_ID128_NULL)) {
                                char as_uuid[37];

                                if (asprintf((char**)(envp + n_env++), "container_uuid=%s", id128_format_as_uuid(arg_uuid, as_uuid)) < 0) {
                                        log_oom();
                                        goto child_fail;
                                }
                        }

                        if (fdset_size(fds) > 0) {
                                k = fdset_cloexec(fds, false);
                                if (k < 0) {
                                        log_error("Failed to unset O_CLOEXEC for file descriptors.");
                                        goto child_fail;
                                }

                                if ((asprintf((char **)(envp + n_env++), "LISTEN_FDS=%u", n_fd_passed) < 0) ||
                                    (asprintf((char **)(envp + n_env++), "LISTEN_PID=1") < 0)) {
                                        log_oom();
                                        goto child_fail;
                                }
                        }

                        setup_hostname();

                        if (arg_personality != 0xffffffffLU) {
                                if (personality(arg_personality) < 0) {
                                        log_error("personality() failed: %m");
                                        goto child_fail;
                                }
                        } else if (secondary) {
                                if (personality(PER_LINUX32) < 0) {
                                        log_error("personality() failed: %m");
                                        goto child_fail;
                                }
                        }

#ifdef HAVE_SELINUX
                        if (arg_selinux_context)
                                if (setexeccon((security_context_t) arg_selinux_context) < 0) {
                                        log_error("setexeccon(\"%s\") failed: %m", arg_selinux_context);
                                        goto child_fail;
                                }
#endif

                        if (!strv_isempty(arg_setenv)) {
                                char **n;

                                n = strv_env_merge(2, envp, arg_setenv);
                                if (!n) {
                                        log_oom();
                                        goto child_fail;
                                }

                                env_use = n;
                        } else
                                env_use = (char**) envp;

                        /* Wait until the parent is ready with the setup, too... */
                        r = eventfd_parent_succeeded(eventfds[0]);
                        eventfds[0] = safe_close(eventfds[0]);
                        if (r < 0)
                                goto child_fail;

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

                        log_error("execv() failed: %m");

                child_fail:
                        /* Tell the parent that the setup failed, so he
                         * can clean up resources and terminate. */
                        if (eventfds[1] != -1)
                                eventfd_send_state(eventfds[1],
                                                   EVENTFD_CHILD_FAILED);
                        _exit(EXIT_FAILURE);
                }

                fdset_free(fds);
                fds = NULL;

                /* Wait for the child event:
                 * If EVENTFD_CHILD_FAILED, the child will terminate soon.
                 * If EVENTFD_CHILD_SUCCEEDED, the child is reporting that
                 * it is ready with all it needs to do with priviliges.
                 * After we got the notification we can make the process
                 * join its cgroup which might limit what it can do */
                r = eventfd_child_succeeded(eventfds[1]);
                eventfds[1] = safe_close(eventfds[1]);

                if (r >= 0) {
                        r = register_machine(pid);
                        if (r < 0)
                                goto finish;

                        r = move_network_interfaces(pid);
                        if (r < 0)
                                goto finish;

                        r = setup_veth(pid, veth_name);
                        if (r < 0)
                                goto finish;

                        r = setup_bridge(veth_name);
                        if (r < 0)
                                goto finish;

                        r = setup_macvlan(pid);
                        if (r < 0)
                                goto finish;

                        /* Block SIGCHLD here, before notifying child.
                         * process_pty() will handle it with the other signals. */
                        r = sigprocmask(SIG_BLOCK, &mask_chld, NULL);
                        if (r < 0)
                                goto finish;

                        /* Reset signal to default */
                        r = default_signals(SIGCHLD, -1);
                        if (r < 0)
                                goto finish;

                        /* Notify the child that the parent is ready with all
                         * its setup, and that the child can now hand over
                         * control to the code to run inside the container. */
                        r = eventfd_send_state(eventfds[0], EVENTFD_PARENT_SUCCEEDED);
                        eventfds[0] = safe_close(eventfds[0]);
                        if (r < 0)
                                goto finish;

                        k = process_pty(master, &mask, arg_boot ? pid : 0, SIGRTMIN+3);
                        if (k < 0) {
                                r = EXIT_FAILURE;
                                break;
                        }

                        if (!arg_quiet)
                                putc('\n', stdout);

                        /* Kill if it is not dead yet anyway */
                        terminate_machine(pid);
                }

                /* Normally redundant, but better safe than sorry */
                kill(pid, SIGKILL);

                r = wait_for_container(pid, &container_status);
                pid = 0;

                if (r < 0) {
                        /* We failed to wait for the container, or the
                         * container exited abnormally */
                        r = EXIT_FAILURE;
                        break;
                } else if (r > 0 || container_status == CONTAINER_TERMINATED)
                        /* The container exited with a non-zero
                         * status, or with zero status and no reboot
                         * was requested. */
                        break;

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
                        r = 133;
                        break;
                }
        }

finish:
        loop_remove(loop_nr, &image_fd);

        if (pid > 0)
                kill(pid, SIGKILL);

        free(arg_directory);
        free(arg_machine);
        free(arg_user);
        strv_free(arg_setenv);
        strv_free(arg_network_interfaces);
        strv_free(arg_network_macvlan);
        strv_free(arg_bind);
        strv_free(arg_bind_ro);
        strv_free(arg_tmpfs);

        return r;
}
