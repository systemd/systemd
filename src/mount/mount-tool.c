/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-wait-for-jobs.h"
#include "device-util.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "libmount-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "sort-util.h"
#include "spawn-polkit-agent.h"
#include "stat-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-def.h"
#include "unit-name.h"
#include "user-util.h"

enum {
        ACTION_DEFAULT,
        ACTION_MOUNT,
        ACTION_AUTOMOUNT,
        ACTION_UMOUNT,
        ACTION_LIST,
} arg_action = ACTION_DEFAULT;

static bool arg_no_block = false;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_full = false;
static bool arg_ask_password = true;
static bool arg_quiet = false;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static bool arg_user = false;
static const char *arg_host = NULL;
static bool arg_discover = false;
static char *arg_mount_what = NULL;
static char *arg_mount_where = NULL;
static char *arg_mount_type = NULL;
static char *arg_mount_options = NULL;
static char *arg_description = NULL;
static char **arg_property = NULL;
static usec_t arg_timeout_idle = USEC_INFINITY;
static bool arg_timeout_idle_set = false;
static char **arg_automount_property = NULL;
static int arg_bind_device = -1;
static uid_t arg_uid = UID_INVALID;
static gid_t arg_gid = GID_INVALID;
static bool arg_fsck = true;
static bool arg_aggressive_gc = false;

STATIC_DESTRUCTOR_REGISTER(arg_mount_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_mount_where, freep);
STATIC_DESTRUCTOR_REGISTER(arg_mount_type, freep);
STATIC_DESTRUCTOR_REGISTER(arg_mount_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_description, freep);
STATIC_DESTRUCTOR_REGISTER(arg_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_automount_property, strv_freep);

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-mount", "1", &link);
        if (r < 0)
                return log_oom();

        printf("systemd-mount [OPTIONS...] WHAT [WHERE]\n"
               "systemd-mount [OPTIONS...] --list\n"
               "%s [OPTIONS...] %sWHAT|WHERE...\n\n"
               "Establish a mount or auto-mount point transiently.\n\n"
               "  -h --help                       Show this help\n"
               "     --version                    Show package version\n"
               "     --no-block                   Do not wait until operation finished\n"
               "     --no-pager                   Do not pipe output into a pager\n"
               "     --no-legend                  Do not show the headers\n"
               "  -l --full                       Do not ellipsize output\n"
               "     --no-ask-password            Do not prompt for password\n"
               "  -q --quiet                      Suppress information messages during runtime\n"
               "     --user                       Run as user unit\n"
               "  -H --host=[USER@]HOST           Operate on remote host\n"
               "  -M --machine=CONTAINER          Operate on local container\n"
               "     --discover                   Discover mount device metadata\n"
               "  -t --type=TYPE                  File system type\n"
               "  -o --options=OPTIONS            Mount options\n"
               "     --owner=USER                 Add uid= and gid= options for USER\n"
               "     --fsck=no                    Don't run file system check before mount\n"
               "     --description=TEXT           Description for unit\n"
               "  -p --property=NAME=VALUE        Set mount unit property\n"
               "  -A --automount=BOOL             Create an auto-mount point\n"
               "     --timeout-idle-sec=SEC       Specify automount idle timeout\n"
               "     --automount-property=NAME=VALUE\n"
               "                                  Set automount unit property\n"
               "     --bind-device                Bind automount unit to device\n"
               "     --list                       List mountable block devices\n"
               "  -u --umount                     Unmount mount points\n"
               "  -G --collect                    Unload unit after it stopped, even when failed\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               streq(program_invocation_short_name, "systemd-umount") ? "" : "--umount ",
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_BLOCK,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_NO_ASK_PASSWORD,
                ARG_USER,
                ARG_SYSTEM,
                ARG_DISCOVER,
                ARG_MOUNT_TYPE,
                ARG_MOUNT_OPTIONS,
                ARG_OWNER,
                ARG_FSCK,
                ARG_DESCRIPTION,
                ARG_TIMEOUT_IDLE,
                ARG_AUTOMOUNT,
                ARG_AUTOMOUNT_PROPERTY,
                ARG_BIND_DEVICE,
                ARG_LIST,
        };

        static const struct option options[] = {
                { "help",               no_argument,       NULL, 'h'                    },
                { "version",            no_argument,       NULL, ARG_VERSION            },
                { "no-block",           no_argument,       NULL, ARG_NO_BLOCK           },
                { "no-pager",           no_argument,       NULL, ARG_NO_PAGER           },
                { "no-legend",          no_argument,       NULL, ARG_NO_LEGEND          },
                { "full",               no_argument,       NULL, 'l'                    },
                { "no-ask-password",    no_argument,       NULL, ARG_NO_ASK_PASSWORD    },
                { "quiet",              no_argument,       NULL, 'q'                    },
                { "user",               no_argument,       NULL, ARG_USER               },
                { "system",             no_argument,       NULL, ARG_SYSTEM             },
                { "host",               required_argument, NULL, 'H'                    },
                { "machine",            required_argument, NULL, 'M'                    },
                { "discover",           no_argument,       NULL, ARG_DISCOVER           },
                { "type",               required_argument, NULL, 't'                    },
                { "options",            required_argument, NULL, 'o'                    },
                { "owner",              required_argument, NULL, ARG_OWNER              },
                { "fsck",               required_argument, NULL, ARG_FSCK               },
                { "description",        required_argument, NULL, ARG_DESCRIPTION        },
                { "property",           required_argument, NULL, 'p'                    },
                { "automount",          required_argument, NULL, ARG_AUTOMOUNT          },
                { "timeout-idle-sec",   required_argument, NULL, ARG_TIMEOUT_IDLE       },
                { "automount-property", required_argument, NULL, ARG_AUTOMOUNT_PROPERTY },
                { "bind-device",        no_argument,       NULL, ARG_BIND_DEVICE        },
                { "list",               no_argument,       NULL, ARG_LIST               },
                { "umount",             no_argument,       NULL, 'u'                    },
                { "unmount",            no_argument,       NULL, 'u'                    },
                { "collect",            no_argument,       NULL, 'G'                    },
                {},
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        if (invoked_as(argv, "systemd-umount"))
                arg_action = ACTION_UMOUNT;

        while ((c = getopt_long(argc, argv, "hqH:M:t:o:p:AuGl", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case ARG_NO_ASK_PASSWORD:
                        arg_ask_password = false;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_USER:
                        arg_user = true;
                        break;

                case ARG_SYSTEM:
                        arg_user = false;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case ARG_DISCOVER:
                        arg_discover = true;
                        break;

                case 't':
                        r = free_and_strdup_warn(&arg_mount_type, optarg);
                        if (r < 0)
                                return r;
                        break;

                case 'o':
                        r = free_and_strdup_warn(&arg_mount_options, optarg);
                        if (r < 0)
                                return r;
                        break;

                case ARG_OWNER: {
                        const char *user = optarg;

                        r = get_user_creds(&user, &arg_uid, &arg_gid, NULL, NULL, 0);
                        if (r < 0)
                                return log_error_errno(r,
                                                       r == -EBADMSG ? "UID or GID of user %s are invalid."
                                                                     : "Cannot use \"%s\" as owner: %m",
                                                       optarg);
                        break;
                }

                case ARG_FSCK:
                        r = parse_boolean_argument("--fsck=", optarg, &arg_fsck);
                        if (r < 0)
                                return r;
                        break;

                case ARG_DESCRIPTION:
                        r = free_and_strdup_warn(&arg_description, optarg);
                        if (r < 0)
                                return r;
                        break;

                case 'p':
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case 'A':
                        arg_action = ACTION_AUTOMOUNT;
                        break;

                case ARG_AUTOMOUNT:
                        r = parse_boolean_argument("--automount=", optarg, NULL);
                        if (r < 0)
                                return r;

                        arg_action = r ? ACTION_AUTOMOUNT : ACTION_MOUNT;
                        break;

                case ARG_TIMEOUT_IDLE:
                        r = parse_sec(optarg, &arg_timeout_idle);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse timeout: %s", optarg);

                        break;

                case ARG_AUTOMOUNT_PROPERTY:
                        if (strv_extend(&arg_automount_property, optarg) < 0)
                                return log_oom();

                        break;

                case ARG_BIND_DEVICE:
                        arg_bind_device = true;
                        break;

                case ARG_LIST:
                        arg_action = ACTION_LIST;
                        break;

                case 'u':
                        arg_action = ACTION_UMOUNT;
                        break;

                case 'G':
                        arg_aggressive_gc = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_user)
                arg_ask_password = false;

        if (arg_user && arg_transport != BUS_TRANSPORT_LOCAL)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Execution in user context is not supported on non-local systems.");

        if (arg_action == ACTION_LIST) {
                if (optind < argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Too many arguments.");

                if (arg_transport != BUS_TRANSPORT_LOCAL)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Listing devices only supported locally.");
        } else if (arg_action == ACTION_UMOUNT) {
                if (optind >= argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "At least one argument required.");

                if (arg_transport != BUS_TRANSPORT_LOCAL) {
                        int i;

                        for (i = optind; i < argc; i++)
                                if (!path_is_absolute(argv[i]) )
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Only absolute path is supported: %s", argv[i]);
                }
        } else {
                if (optind >= argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "At least one argument required.");

                if (argc > optind+2)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "At most two arguments required.");

                if (arg_mount_type && !fstype_is_blockdev_backed(arg_mount_type)) {
                        arg_mount_what = strdup(argv[optind]);
                        if (!arg_mount_what)
                                return log_oom();

                } else if (arg_transport == BUS_TRANSPORT_LOCAL) {
                        _cleanup_free_ char *u = NULL;

                        u = fstab_node_to_udev_node(argv[optind]);
                        if (!u)
                                return log_oom();

                        r = chase_symlinks(u, NULL, 0, &arg_mount_what, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make path %s absolute: %m", u);
                } else {
                        arg_mount_what = strdup(argv[optind]);
                        if (!arg_mount_what)
                                return log_oom();

                        path_simplify(arg_mount_what);

                        if (!path_is_absolute(arg_mount_what))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Only absolute path is supported: %s", arg_mount_what);
                }

                if (argc > optind+1) {
                        if (arg_transport == BUS_TRANSPORT_LOCAL) {
                                r = chase_symlinks(argv[optind+1], NULL, CHASE_NONEXISTENT, &arg_mount_where, NULL);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to make path %s absolute: %m", argv[optind+1]);
                        } else {
                                arg_mount_where = strdup(argv[optind+1]);
                                if (!arg_mount_where)
                                        return log_oom();

                                path_simplify(arg_mount_where);

                                if (!path_is_absolute(arg_mount_where))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Only absolute path is supported: %s", arg_mount_where);
                        }
                } else
                        arg_discover = true;

                if (arg_discover && arg_transport != BUS_TRANSPORT_LOCAL)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Automatic mount location discovery is only supported locally.");
        }

        return 1;
}

static int transient_unit_set_properties(sd_bus_message *m, UnitType t, char **properties) {
        int r;

        if (!isempty(arg_description)) {
                r = sd_bus_message_append(m, "(sv)", "Description", "s", arg_description);
                if (r < 0)
                        return r;
        }

        if (arg_bind_device && is_device_path(arg_mount_what)) {
                _cleanup_free_ char *device_unit = NULL;

                r = unit_name_from_path(arg_mount_what, ".device", &device_unit);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m, "(sv)(sv)",
                                          "After", "as", 1, device_unit,
                                          "BindsTo", "as", 1, device_unit);
                if (r < 0)
                        return r;
        }

        if (arg_aggressive_gc) {
                r = sd_bus_message_append(m, "(sv)", "CollectMode", "s", "inactive-or-failed");
                if (r < 0)
                        return r;
        }

        r = bus_append_unit_property_assignment_many(m, t, properties);
        if (r < 0)
                return r;

        return 0;
}

static int transient_mount_set_properties(sd_bus_message *m) {
        _cleanup_free_ char *options = NULL;
        int r;

        assert(m);

        r = transient_unit_set_properties(m, UNIT_MOUNT, arg_property);
        if (r < 0)
                return r;

        if (arg_mount_what) {
                r = sd_bus_message_append(m, "(sv)", "What", "s", arg_mount_what);
                if (r < 0)
                        return r;
        }

        if (arg_mount_type) {
                r = sd_bus_message_append(m, "(sv)", "Type", "s", arg_mount_type);
                if (r < 0)
                        return r;
        }

        /* Prepend uid=…,gid=… if arg_uid is set */
        if (arg_uid != UID_INVALID) {
                r = asprintf(&options,
                             "uid=" UID_FMT ",gid=" GID_FMT "%s%s",
                             arg_uid, arg_gid,
                             arg_mount_options ? "," : "", strempty(arg_mount_options));
                if (r < 0)
                        return -ENOMEM;
        }

        if (options || arg_mount_options) {
                log_debug("Using mount options: %s", options ?: arg_mount_options);

                r = sd_bus_message_append(m, "(sv)", "Options", "s", options ?: arg_mount_options);
                if (r < 0)
                        return r;
        } else
                log_debug("Not using any mount options");

        if (arg_fsck) {
                _cleanup_free_ char *fsck = NULL;

                r = unit_name_from_path_instance("systemd-fsck", arg_mount_what, ".service", &fsck);
                if (r < 0)
                        return r;

                r = sd_bus_message_append(m,
                                          "(sv)(sv)",
                                          "Requires", "as", 1, fsck,
                                          "After", "as", 1, fsck);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int transient_automount_set_properties(sd_bus_message *m) {
        int r;

        assert(m);

        r = transient_unit_set_properties(m, UNIT_AUTOMOUNT, arg_automount_property);
        if (r < 0)
                return r;

        if (arg_timeout_idle != USEC_INFINITY) {
                r = sd_bus_message_append(m, "(sv)", "TimeoutIdleUSec", "t", arg_timeout_idle);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int start_transient_mount(
                sd_bus *bus,
                char **argv) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *mount_unit = NULL;
        int r;

        if (!arg_no_block) {
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        r = unit_name_from_path(arg_mount_where, ".mount", &mount_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to make mount unit name: %m");

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_allow_interactive_authorization(m, arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and mode */
        r = sd_bus_message_append(m, "ss", mount_unit, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = transient_mount_set_properties(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient mount unit: %s", bus_error_message(&error, r));

        if (w) {
                const char *object;

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_one(w, object, arg_quiet);
                if (r < 0)
                        return r;
        }

        if (!arg_quiet)
                log_info("Started unit %s%s%s for mount point: %s%s%s",
                         ansi_highlight(), mount_unit, ansi_normal(),
                         ansi_highlight(), arg_mount_where, ansi_normal());

        return 0;
}

static int start_transient_automount(
                sd_bus *bus,
                char **argv) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *automount_unit = NULL, *mount_unit = NULL;
        int r;

        if (!arg_no_block) {
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        r = unit_name_from_path(arg_mount_where, ".automount", &automount_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to make automount unit name: %m");

        r = unit_name_from_path(arg_mount_where, ".mount", &mount_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to make mount unit name: %m");

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StartTransientUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_allow_interactive_authorization(m, arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and mode */
        r = sd_bus_message_append(m, "ss", automount_unit, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        /* Properties */
        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = transient_automount_set_properties(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Auxiliary units */
        r = sd_bus_message_open_container(m, 'a', "(sa(sv))");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'r', "sa(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", mount_unit);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = transient_mount_set_properties(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient automount unit: %s", bus_error_message(&error, r));

        if (w) {
                const char *object;

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_one(w, object, arg_quiet);
                if (r < 0)
                        return r;
        }

        if (!arg_quiet)
                log_info("Started unit %s%s%s for mount point: %s%s%s",
                         ansi_highlight(), automount_unit, ansi_normal(),
                         ansi_highlight(), arg_mount_where, ansi_normal());

        return 0;
}

static int find_mount_points(const char *what, char ***list) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        _cleanup_strv_free_ char **l = NULL;
        size_t n = 0;
        int r;

        assert(what);
        assert(list);

        /* Returns all mount points obtained from /proc/self/mountinfo in *list,
         * and the number of mount points as return value. */

        r = libmount_parse(NULL, NULL, &table, &iter);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        for (;;) {
                struct libmnt_fs *fs;
                const char *source, *target;

                r = mnt_table_next_fs(table, iter, &fs);
                if (r == 1)
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                source = mnt_fs_get_source(fs);
                target = mnt_fs_get_target(fs);
                if (!source || !target)
                        continue;

                if (!path_equal(source, what))
                        continue;

                /* one extra slot is needed for the terminating NULL */
                if (!GREEDY_REALLOC0(l, n + 2))
                        return log_oom();

                l[n] = strdup(target);
                if (!l[n])
                        return log_oom();
                n++;
        }

        if (!GREEDY_REALLOC0(l, n + 1))
                return log_oom();

        *list = TAKE_PTR(l);
        return n;
}

static int find_loop_device(const char *backing_file, char **loop_dev) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        _cleanup_free_ char *l = NULL;

        assert(backing_file);
        assert(loop_dev);

        d = opendir("/sys/devices/virtual/block");
        if (!d)
                return -errno;

        FOREACH_DIRENT(de, d, return -errno) {
                _cleanup_free_ char *sys = NULL, *fname = NULL;
                int r;

                if (de->d_type != DT_DIR)
                        continue;

                if (!startswith(de->d_name, "loop"))
                        continue;

                sys = path_join("/sys/devices/virtual/block", de->d_name, "loop/backing_file");
                if (!sys)
                        return -ENOMEM;

                r = read_one_line_file(sys, &fname);
                if (r < 0) {
                        log_debug_errno(r, "Failed to read %s, ignoring: %m", sys);
                        continue;
                }

                if (files_same(fname, backing_file, 0) <= 0)
                        continue;

                l = path_join("/dev", de->d_name);
                if (!l)
                        return -ENOMEM;

                break;
        }

        if (!l)
                return -ENXIO;

        *loop_dev = TAKE_PTR(l);

        return 0;
}

static int stop_mount(
                sd_bus *bus,
                const char *where,
                const char *suffix) {

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *mount_unit = NULL;
        int r;

        if (!arg_no_block) {
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        r = unit_name_from_path(where, suffix, &mount_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to make %s unit name from path %s: %m", suffix + 1, where);

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StopUnit");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_allow_interactive_authorization(m, arg_ask_password);
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and mode */
        r = sd_bus_message_append(m, "ss", mount_unit, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                if (streq(suffix, ".automount") &&
                    sd_bus_error_has_name(&error, "org.freedesktop.systemd1.NoSuchUnit"))
                        return 0;
                return log_error_errno(r, "Failed to stop %s unit: %s", suffix + 1, bus_error_message(&error, r));
        }

        if (w) {
                const char *object;

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_one(w, object, arg_quiet);
                if (r < 0)
                        return r;
        }

        if (!arg_quiet)
                log_info("Stopped unit %s%s%s for mount point: %s%s%s",
                         ansi_highlight(), mount_unit, ansi_normal(),
                         ansi_highlight(), where, ansi_normal());

        return 0;
}

static int stop_mounts(
                sd_bus *bus,
                const char *where) {

        int r;

        if (path_equal(where, "/"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Refusing to operate on root directory: %s", where);

        if (!path_is_normalized(where))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path contains non-normalized components: %s", where);

        r = stop_mount(bus, where, ".mount");
        if (r < 0)
                return r;

        r = stop_mount(bus, where, ".automount");
        if (r < 0)
                return r;

        return 0;
}

static int umount_by_device(sd_bus *bus, const char *what) {
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_strv_free_ char **list = NULL;
        struct stat st;
        const char *v;
        char **l;
        int r, r2 = 0;

        assert(what);

        if (stat(what, &st) < 0)
                return log_error_errno(errno, "Can't stat %s: %m", what);

        if (!S_ISBLK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTBLK),
                                       "Not a block device: %s", what);

        r = sd_device_new_from_stat_rdev(&d, &st);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from device number: %m");

        r = sd_device_get_property_value(d, "ID_FS_USAGE", &v);
        if (r < 0)
                return log_device_error_errno(d, r, "Failed to get device property: %m");

        if (!streq(v, "filesystem"))
                return log_device_error_errno(d, SYNTHETIC_ERRNO(EINVAL),
                                              "%s does not contain a known file system.", what);

        if (sd_device_get_property_value(d, "SYSTEMD_MOUNT_WHERE", &v) >= 0)
                r2 = stop_mounts(bus, v);

        r = find_mount_points(what, &list);
        if (r < 0)
                return r;

        for (l = list; *l; l++) {
                r = stop_mounts(bus, *l);
                if (r < 0)
                        r2 = r;
        }

        return r2;
}

static int umount_loop(sd_bus *bus, const char *backing_file) {
        _cleanup_free_ char *loop_dev = NULL;
        int r;

        assert(backing_file);

        r = find_loop_device(backing_file, &loop_dev);
        if (r < 0)
                return log_error_errno(r, r == -ENXIO ? "File %s is not mounted." : "Can't get loop device for %s: %m", backing_file);

        return umount_by_device(bus, loop_dev);
}

static int action_umount(
                sd_bus *bus,
                int argc,
                char **argv) {

        int i, r, r2 = 0;

        if (arg_transport != BUS_TRANSPORT_LOCAL) {
                for (i = optind; i < argc; i++) {
                        _cleanup_free_ char *p = NULL;

                        p = strdup(argv[i]);
                        if (!p)
                                return log_oom();

                        path_simplify(p);

                        r = stop_mounts(bus, p);
                        if (r < 0)
                                r2 = r;
                }
                return r2;
        }

        for (i = optind; i < argc; i++) {
                _cleanup_free_ char *u = NULL, *p = NULL;
                struct stat st;

                u = fstab_node_to_udev_node(argv[i]);
                if (!u)
                        return log_oom();

                r = chase_symlinks(u, NULL, 0, &p, NULL);
                if (r < 0) {
                        r2 = log_error_errno(r, "Failed to make path %s absolute: %m", argv[i]);
                        continue;
                }

                if (stat(p, &st) < 0)
                        return log_error_errno(errno, "Can't stat %s (from %s): %m", p, argv[i]);

                if (S_ISBLK(st.st_mode))
                        r = umount_by_device(bus, p);
                else if (S_ISREG(st.st_mode))
                        r = umount_loop(bus, p);
                else if (S_ISDIR(st.st_mode))
                        r = stop_mounts(bus, p);
                else {
                        log_error("Invalid file type: %s (from %s)", p, argv[i]);
                        r = -EINVAL;
                }

                if (r < 0)
                        r2 = r;
        }

        return r2;
}

static int acquire_mount_type(sd_device *d) {
        const char *v;

        assert(d);

        if (arg_mount_type)
                return 0;

        if (sd_device_get_property_value(d, "ID_FS_TYPE", &v) < 0)
                return 0;

        arg_mount_type = strdup(v);
        if (!arg_mount_type)
                return log_oom();

        log_debug("Discovered type=%s", arg_mount_type);
        return 1;
}

static int acquire_mount_options(sd_device *d) {
        const char *v;

        assert(d);

        if (arg_mount_options)
                return 0;

        if (sd_device_get_property_value(d, "SYSTEMD_MOUNT_OPTIONS", &v) < 0)
                return 0;

        arg_mount_options = strdup(v);
        if (!arg_mount_options)
                return log_oom();

        log_debug("Discovered options=%s", arg_mount_options);
        return 1;
}

static const char *get_model(sd_device *d) {
        const char *model;

        assert(d);

        if (sd_device_get_property_value(d, "ID_MODEL_FROM_DATABASE", &model) >= 0)
                return model;

        if (sd_device_get_property_value(d, "ID_MODEL", &model) >= 0)
                return model;

        return NULL;
}

static const char* get_label(sd_device *d) {
        const char *label;

        assert(d);

        if (sd_device_get_property_value(d, "ID_FS_LABEL", &label) >= 0)
                return label;

        if (sd_device_get_property_value(d, "ID_PART_ENTRY_NAME", &label) >= 0)
                return label;

        return NULL;
}

static int acquire_mount_where(sd_device *d) {
        const char *v;

        if (arg_mount_where)
                return 0;

        if (sd_device_get_property_value(d, "SYSTEMD_MOUNT_WHERE", &v) < 0) {
                _cleanup_free_ char *escaped = NULL;
                const char *name;

                name = get_label(d);
                if (!name)
                        name = get_model(d);
                if (!name) {
                        const char *dn;

                        if (sd_device_get_devname(d, &dn) < 0)
                                return 0;

                        name = basename(dn);
                }

                escaped = xescape(name, "\\");
                if (!escaped)
                        return log_oom();
                if (!filename_is_valid(escaped))
                        return 0;

                arg_mount_where = path_join("/run/media/system", escaped);
        } else
                arg_mount_where = strdup(v);

        if (!arg_mount_where)
                return log_oom();

        log_debug("Discovered where=%s", arg_mount_where);
        return 1;
}

static int acquire_mount_where_for_loop_dev(const char *loop_dev) {
        _cleanup_strv_free_ char **list = NULL;
        int r;

        if (arg_mount_where)
                return 0;

        r = find_mount_points(loop_dev, &list);
        if (r < 0)
                return r;
        else if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Can't find mount point of %s. It is expected that %s is already mounted on a place.",
                                       loop_dev, loop_dev);
        else if (r >= 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s is mounted on %d places. It is expected that %s is mounted on a place.",
                                       loop_dev, r, loop_dev);

        arg_mount_where = strdup(list[0]);
        if (!arg_mount_where)
                return log_oom();

        log_debug("Discovered where=%s", arg_mount_where);
        return 1;
}

static int acquire_description(sd_device *d) {
        const char *model, *label;

        if (arg_description)
                return 0;

        model = get_model(d);

        label = get_label(d);
        if (!label)
                (void) sd_device_get_property_value(d, "ID_PART_ENTRY_NUMBER", &label);

        if (model && label)
                arg_description = strjoin(model, " ", label);
        else if (label)
                arg_description = strdup(label);
        else if (model)
                arg_description = strdup(model);
        else
                return 0;

        if (!arg_description)
                return log_oom();

        log_debug("Discovered description=%s", arg_description);
        return 1;
}

static int acquire_removable(sd_device *d) {
        const char *v;

        /* Shortcut this if there's no reason to check it */
        if (arg_action != ACTION_DEFAULT && arg_timeout_idle_set && arg_bind_device >= 0)
                return 0;

        for (;;) {
                if (sd_device_get_sysattr_value(d, "removable", &v) >= 0)
                        break;

                if (sd_device_get_parent(d, &d) < 0)
                        return 0;

                if (sd_device_get_subsystem(d, &v) < 0 || !streq(v, "block"))
                        return 0;
        }

        if (parse_boolean(v) <= 0)
                return 0;

        log_debug("Discovered removable device.");

        if (arg_action == ACTION_DEFAULT) {
                log_debug("Automatically turning on automount.");
                arg_action = ACTION_AUTOMOUNT;
        }

        if (!arg_timeout_idle_set) {
                log_debug("Setting idle timeout to 1s.");
                arg_timeout_idle = USEC_PER_SEC;
        }

        if (arg_bind_device < 0) {
                log_debug("Binding automount unit to device.");
                arg_bind_device = true;
        }

        return 1;
}

static int discover_loop_backing_file(void) {
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_free_ char *loop_dev = NULL;
        struct stat st;
        const char *v;
        int r;

        r = find_loop_device(arg_mount_what, &loop_dev);
        if (r < 0 && r != -ENXIO)
                return log_error_errno(errno, "Can't get loop device for %s: %m", arg_mount_what);

        if (r == -ENXIO) {
                _cleanup_free_ char *escaped = NULL;

                if (arg_mount_where)
                        return 0;

                escaped = xescape(basename(arg_mount_what), "\\");
                if (!escaped)
                        return log_oom();
                if (!filename_is_valid(escaped))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Escaped name %s is not a valid filename.",
                                               escaped);

                arg_mount_where = path_join("/run/media/system", escaped);
                if (!arg_mount_where)
                        return log_oom();

                log_debug("Discovered where=%s", arg_mount_where);
                return 0;
        }

        if (stat(loop_dev, &st) < 0)
                return log_error_errno(errno, "Can't stat %s: %m", loop_dev);

        if (!S_ISBLK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid file type: %s", loop_dev);

        r = sd_device_new_from_stat_rdev(&d, &st);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from device number: %m");

        if (sd_device_get_property_value(d, "ID_FS_USAGE", &v) < 0 || !streq(v, "filesystem"))
                return log_device_error_errno(d, SYNTHETIC_ERRNO(EINVAL),
                                              "%s does not contain a known file system.", arg_mount_what);

        r = acquire_mount_type(d);
        if (r < 0)
                return r;

        r = acquire_mount_options(d);
        if (r < 0)
                return r;

        r = acquire_mount_where_for_loop_dev(loop_dev);
        if (r < 0)
                return r;

        r = acquire_description(d);
        if (r < 0)
                return r;

        return 0;
}

static int discover_device(void) {
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        struct stat st;
        const char *v;
        int r;

        if (stat(arg_mount_what, &st) < 0)
                return log_error_errno(errno, "Can't stat %s: %m", arg_mount_what);

        if (S_ISREG(st.st_mode))
                return discover_loop_backing_file();

        if (!S_ISBLK(st.st_mode))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid file type: %s",
                                       arg_mount_what);

        r = sd_device_new_from_stat_rdev(&d, &st);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from device number: %m");

        if (sd_device_get_property_value(d, "ID_FS_USAGE", &v) < 0 || !streq(v, "filesystem"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s does not contain a known file system.",
                                       arg_mount_what);

        r = acquire_mount_type(d);
        if (r < 0)
                return r;

        r = acquire_mount_options(d);
        if (r < 0)
                return r;

        r = acquire_mount_where(d);
        if (r < 0)
                return r;

        r = acquire_description(d);
        if (r < 0)
                return r;

        r = acquire_removable(d);
        if (r < 0)
                return r;

        return 0;
}

enum {
        COLUMN_NODE,
        COLUMN_PATH,
        COLUMN_MODEL,
        COLUMN_WWN,
        COLUMN_FSTYPE,
        COLUMN_LABEL,
        COLUMN_UUID,
        _COLUMN_MAX,
};

static int list_devices(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        sd_device *d;
        unsigned c;
        int r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_oom();

        r = sd_device_enumerator_add_match_subsystem(e, "block", true);
        if (r < 0)
                return log_error_errno(r, "Failed to add block match: %m");

        r = sd_device_enumerator_add_match_property(e, "ID_FS_USAGE", "filesystem");
        if (r < 0)
                return log_error_errno(r, "Failed to add property match: %m");

        table = table_new("NODE", "PATH", "MODEL", "WWN", "TYPE", "LABEL", "UUID");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        r = table_set_sort(table, (size_t) 0);
        if (r < 0)
                return log_error_errno(r, "Failed to set sort index: %m");

        table_set_header(table, arg_legend);

        FOREACH_DEVICE(e, d) {
                for (c = 0; c < _COLUMN_MAX; c++) {
                        const char *x = NULL;

                        switch (c) {

                        case COLUMN_NODE:
                                (void) sd_device_get_devname(d, &x);
                                break;

                        case COLUMN_PATH:
                                (void) sd_device_get_property_value(d, "ID_PATH", &x);
                                break;

                        case COLUMN_MODEL:
                                x = get_model(d);
                                break;

                        case COLUMN_WWN:
                                (void) sd_device_get_property_value(d, "ID_WWN", &x);
                                break;

                        case COLUMN_FSTYPE:
                                (void) sd_device_get_property_value(d, "ID_FS_TYPE", &x);
                                break;

                        case COLUMN_LABEL:
                                x = get_label(d);
                                break;

                        case COLUMN_UUID:
                                (void) sd_device_get_property_value(d, "ID_FS_UUID", &x);
                                break;
                        }

                        r = table_add_cell(table, NULL, c == COLUMN_NODE ? TABLE_PATH : TABLE_STRING, strna(x));
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        (void) pager_open(arg_pager_flags);

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int run(int argc, char* argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_action == ACTION_LIST)
                return list_devices();

        r = bus_connect_transport_systemd(arg_transport, arg_host, arg_user, &bus);
        if (r < 0)
                return bus_log_connect_error(r);

        if (arg_action == ACTION_UMOUNT)
                return action_umount(bus, argc, argv);

        if ((!arg_mount_type || fstype_is_blockdev_backed(arg_mount_type))
            && !path_is_normalized(arg_mount_what))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path contains non-normalized components: %s",
                                       arg_mount_what);

        if (arg_discover) {
                r = discover_device();
                if (r < 0)
                        return r;
        }

        if (!arg_mount_where)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Can't figure out where to mount %s.",
                                       arg_mount_what);

        if (path_equal(arg_mount_where, "/"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Refusing to operate on root directory.");

        if (!path_is_normalized(arg_mount_where))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Path contains non-normalized components: %s",
                                       arg_mount_where);

        if (streq_ptr(arg_mount_type, "auto"))
                arg_mount_type = mfree(arg_mount_type);
        if (streq_ptr(arg_mount_options, "defaults"))
                arg_mount_options = mfree(arg_mount_options);

        if (!is_device_path(arg_mount_what))
                arg_fsck = false;

        if (arg_fsck && arg_mount_type && arg_transport == BUS_TRANSPORT_LOCAL) {
                r = fsck_exists(arg_mount_type);
                if (r < 0)
                        log_warning_errno(r, "Couldn't determine whether fsck for %s exists, proceeding anyway.", arg_mount_type);
                else if (r == 0) {
                        log_debug("Disabling file system check as fsck for %s doesn't exist.", arg_mount_type);
                        arg_fsck = false; /* fsck doesn't exist, let's not attempt it */
                }
        }

        /* The kernel (properly) refuses mounting file systems with unknown uid=,gid= options,
         * but not for all filesystem types. Let's try to catch the cases where the option
         * would be used if the file system does not support it. It is also possible to
         * autodetect the file system, but that's only possible with disk-based file systems
         * which incidentally seem to be implemented more carefully and reject unknown options,
         * so it's probably OK that we do the check only when the type is specified.
         */
        if (arg_mount_type &&
            !streq(arg_mount_type, "auto") &&
            arg_uid != UID_INVALID &&
            !fstype_can_uid_gid(arg_mount_type))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "File system type %s is not known to support uid=/gid=, refusing.",
                                       arg_mount_type);

        switch (arg_action) {

        case ACTION_MOUNT:
        case ACTION_DEFAULT:
                r = start_transient_mount(bus, argv + optind);
                break;

        case ACTION_AUTOMOUNT:
                r = start_transient_automount(bus, argv + optind);
                break;

        default:
                assert_not_reached("Unexpected action.");
        }

        return r;
}

DEFINE_MAIN_FUNCTION(run);
