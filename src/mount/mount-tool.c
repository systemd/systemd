/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-bus.h"
#include "sd-device.h"

#include "argv-util.h"
#include "build.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "chase.h"
#include "device-util.h"
#include "errno-util.h"
#include "escape.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "fstab-util.h"
#include "libmount-util.h"
#include "main-func.h"
#include "mountpoint-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "polkit-agent.h"
#include "pretty-print.h"
#include "process-util.h"
#include "runtime-scope.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "udev-util.h"
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
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
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
static bool arg_tmpfs = false;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static bool arg_canonicalize = true;

STATIC_DESTRUCTOR_REGISTER(arg_mount_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_mount_where, freep);
STATIC_DESTRUCTOR_REGISTER(arg_mount_type, freep);
STATIC_DESTRUCTOR_REGISTER(arg_mount_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_description, freep);
STATIC_DESTRUCTOR_REGISTER(arg_property, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_automount_property, strv_freep);

static int parse_where(const char *input, char **ret_where) {
        int r;

        assert(input);
        assert(ret_where);

        if (arg_transport == BUS_TRANSPORT_LOCAL && arg_canonicalize) {
                r = chase(input, /* root= */ NULL, CHASE_NONEXISTENT|CHASE_TRIGGER_AUTOFS, ret_where, /* ret_fd= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to make path %s absolute: %m", input);
        } else {
                if (!path_is_absolute(input))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Path must be absolute when operating remotely or when canonicalization is turned off: %s",
                                               input);

                r = path_simplify_alloc(input, ret_where);
                if (r < 0)
                        return log_error_errno(r, "Failed to simplify path %s: %m", input);
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-mount", "1", &link);
        if (r < 0)
                return log_oom();

        printf("systemd-mount [OPTIONS...] WHAT [WHERE]\n"
               "systemd-mount [OPTIONS...] --tmpfs [NAME] WHERE\n"
               "systemd-mount [OPTIONS...] --list\n"
               "%1$s [OPTIONS...] %7$sWHAT|WHERE...\n"
               "\n%5$sEstablish a mount or auto-mount point transiently.%6$s\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                       Show this help\n"
               "     --version                    Show package version\n"
               "     --no-block                   Do not wait until operation finished\n"
               "     --no-pager                   Do not pipe output into a pager\n"
               "     --no-legend                  Do not show the headers\n"
               "  -l --full                       Do not ellipsize output\n"
               "     --no-ask-password            Do not prompt for password\n"
               "  -q --quiet                      Suppress information messages during runtime\n"
               "     --json=pretty|short|off      Generate JSON output\n"
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
               "     --automount=BOOL             Create an automount point\n"
               "  -A                              Same as --automount=yes\n"
               "     --timeout-idle-sec=SEC       Specify automount idle timeout\n"
               "     --automount-property=NAME=VALUE\n"
               "                                  Set automount unit property\n"
               "     --bind-device                Bind automount unit to device\n"
               "     --list                       List mountable block devices\n"
               "  -u --umount                     Unmount mount points\n"
               "  -G --collect                    Unload unit after it stopped, even when failed\n"
               "  -T --tmpfs                      Create a new tmpfs on the mount point\n"
               "     --canonicalize=BOOL          Controls whether to canonicalize path before\n"
               "                                  operation\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal(),
               streq(program_invocation_short_name, "systemd-umount") ? "" : "--umount ");

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
                ARG_JSON,
                ARG_CANONICALIZE,
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
                { "unmount",            no_argument,       NULL, 'u'                    }, /* Compat spelling */
                { "collect",            no_argument,       NULL, 'G'                    },
                { "tmpfs",              no_argument,       NULL, 'T'                    },
                { "json",               required_argument, NULL, ARG_JSON               },
                { "canonicalize",       required_argument, NULL, ARG_CANONICALIZE       },
                {},
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        if (invoked_as(argv, "systemd-umount"))
                arg_action = ACTION_UMOUNT;

        while ((c = getopt_long(argc, argv, "hqH:M:t:o:p:AuGlT", options, NULL)) >= 0)

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
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        r = parse_machine_argument(optarg, &arg_host, &arg_transport);
                        if (r < 0)
                                return r;
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

                case 'T':
                        arg_tmpfs = true;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case ARG_CANONICALIZE:
                        r = parse_boolean_argument("--canonicalize=", optarg, &arg_canonicalize);
                        if (r < 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_runtime_scope == RUNTIME_SCOPE_USER) {
                arg_ask_password = false;

                if (arg_transport != BUS_TRANSPORT_LOCAL)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Execution in user context is not supported on non-local systems.");
        }

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

                if (arg_transport != BUS_TRANSPORT_LOCAL || !arg_canonicalize)
                        for (int i = optind; i < argc; i++)
                                if (!path_is_absolute(argv[i]))
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                               "Path must be absolute when operating remotely or when canonicalization is turned off: %s",
                                                               argv[i]);
        } else {
                if (optind >= argc)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "At least one argument required.");

                if (argc > optind+2)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "More than two arguments are not allowed.");

                if (arg_tmpfs) {
                        if (arg_discover)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--discover cannot be used in conjunction with --tmpfs.");

                        if (argc <= optind+1) {
                                arg_mount_what = strdup("tmpfs");
                                if (!arg_mount_what)
                                        return log_oom();

                                r = parse_where(argv[optind], &arg_mount_where);
                                if (r < 0)
                                        return r;
                        } else {
                                arg_mount_what = strdup(argv[optind]);
                                if (!arg_mount_what)
                                        return log_oom();
                        }

                        if (!arg_mount_type) {
                                arg_mount_type = strdup("tmpfs");
                                if (!arg_mount_type)
                                        return log_oom();
                        } else if (!streq(arg_mount_type, "tmpfs"))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--tmpfs requested with incompatible --type=, refusing: %s",
                                                       arg_mount_type);
                } else {
                        if (arg_mount_type && !fstype_is_blockdev_backed(arg_mount_type)) {
                                arg_mount_what = strdup(argv[optind]);
                                if (!arg_mount_what)
                                        return log_oom();
                        } else {
                                _cleanup_free_ char *u = NULL;
                                const char *p = argv[optind];

                                if (arg_canonicalize) {
                                        u = fstab_node_to_udev_node(p);
                                        if (!u)
                                                return log_oom();
                                        p = u;
                                }

                                if (arg_transport == BUS_TRANSPORT_LOCAL && arg_canonicalize) {
                                        r = chase(p, /* root= */ NULL, CHASE_TRIGGER_AUTOFS, &arg_mount_what, /* ret_fd= */ NULL);
                                        if (r < 0)
                                                return log_error_errno(r, "Failed to chase path '%s': %m", p);
                                } else {
                                        if (!path_is_absolute(p))
                                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                       "Path must be absolute when operating remotely or when canonicalization is turned off: %s",
                                                                       p);

                                        r = path_simplify_alloc(p, &arg_mount_what);
                                        if (r < 0)
                                                return log_oom();
                                }
                        }
                }

                if (argc > optind+1) {
                        r = parse_where(argv[optind+1], &arg_mount_where);
                        if (r < 0)
                                return r;
                } else if (!arg_tmpfs)
                        arg_discover = true;

                if (arg_discover && arg_transport != BUS_TRANSPORT_LOCAL)
                        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Automatic mount location discovery is only supported locally.");

                _cleanup_free_ char *dev_bound = NULL;
                r = fstab_filter_options(arg_mount_options, "x-systemd.device-bound\0",
                                         /* ret_namefound= */ NULL, &dev_bound, /* ret_values= */ NULL, /* ret_filtered= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse mount options for x-systemd.device-bound=: %m");
                if (r > 0 && !isempty(dev_bound)) {
                        /* If x-systemd.device-bound=no is explicitly specified, never bind automount unit
                         * to device either. */
                        r = parse_boolean(dev_bound);
                        if (r < 0)
                                return log_error_errno(r, "Invalid x-systemd.device-bound= option: %s", dev_bound);
                        if (r == 0) {
                                log_full(arg_bind_device > 0 ? LOG_NOTICE : LOG_DEBUG,
                                         "x-systemd.device-bound=no set, automatically disabling --bind-device.");
                                arg_bind_device = false;
                        }
                }
        }

        return 1;
}

static int transient_unit_set_properties(sd_bus_message *m, UnitType t, char **properties) {
        int r;

        assert(m);
        assert(IN_SET(t, UNIT_MOUNT, UNIT_AUTOMOUNT));

        if (!isempty(arg_description)) {
                r = sd_bus_message_append(m, "(sv)", "Description", "s", arg_description);
                if (r < 0)
                        return r;
        }

        if (arg_bind_device > 0 && is_device_path(arg_mount_what)) {
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

        _cleanup_free_ char *options = NULL;

        /* Prepend uid=…,gid=… if arg_uid is set */
        if (arg_uid != UID_INVALID) {
                r = strextendf_with_separator(&options, ",",
                                              "uid="UID_FMT",gid="GID_FMT, arg_uid, arg_gid);
                if (r < 0)
                        return r;
        }

        /* Override the default for tmpfs mounts. The kernel sets the sticky bit on the root directory by
         * default. This makes sense for the case when the user does 'mount -t tmpfs tmpfs /tmp', but less so
         * for other directories.
         *
         * Let's also set some reasonable limits. We use the current umask, to match what a command to create
         * directory would use, e.g. mkdir. */
        if (arg_tmpfs) {
                mode_t mask;

                r = get_process_umask(0, &mask);
                if (r < 0)
                        return r;

                assert((mask & ~0777) == 0);
                r = strextendf_with_separator(&options, ",",
                                              "mode=0%o,nodev,nosuid%s", 0777 & ~mask, NESTED_TMPFS_LIMITS);
                if (r < 0)
                        return r;
        }

        if (arg_mount_options)
                if (!strextend_with_separator(&options, ",", arg_mount_options))
                        return -ENOMEM;

        if (options) {
                log_debug("Using mount options: %s", options);
                r = sd_bus_message_append(m, "(sv)", "Options", "s", options);
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

static int start_transient_mount(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *mount_unit = NULL;
        int r;

        assert(bus);

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

        /* No auxiliary units */
        r = sd_bus_message_append(m, "a(sa(sv))", 0);
        if (r < 0)
                return bus_log_create_error(r);

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient mount unit: %s", bus_error_message(&error, r));

        if (w) {
                const char *object;

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_one(w, object, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR, NULL);
                if (r < 0)
                        return r;
        }

        if (!arg_quiet)
                log_info("Started unit %s%s%s for mount point: %s%s%s",
                         ansi_highlight(), mount_unit, ansi_normal(),
                         ansi_highlight(), arg_mount_where, ansi_normal());

        return 0;
}

static int start_transient_automount(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *automount_unit = NULL, *mount_unit = NULL;
        int r;

        assert(bus);

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

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to start transient automount unit: %s", bus_error_message(&error, r));

        if (w) {
                const char *object;

                r = sd_bus_message_read(reply, "o", &object);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_one(w, object, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR, NULL);
                if (r < 0)
                        return r;
        }

        if (!arg_quiet)
                log_info("Started unit %s%s%s for mount point: %s%s%s",
                         ansi_highlight(), automount_unit, ansi_normal(),
                         ansi_highlight(), arg_mount_where, ansi_normal());

        return 0;
}

static int find_mount_points_by_source(const char *what, char ***ret) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        _cleanup_strv_free_ char **l = NULL;
        size_t n = 0;
        int r;

        assert(what);
        assert(ret);

        /* Obtain all mount points with source being "what" from /proc/self/mountinfo, return value shows
         * the total number of them. */

        r = libmount_parse_mountinfo(/* source= */ NULL, &table, &iter);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        for (;;) {
                struct libmnt_fs *fs;
                const char *source, *target;

                r = sym_mnt_table_next_fs(table, iter, &fs);
                if (r == 1)
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                source = sym_mnt_fs_get_source(fs);
                target = sym_mnt_fs_get_target(fs);
                if (!source || !target)
                        continue;

                if (!path_equal(source, what))
                        continue;

                r = strv_extend_with_size(&l, &n, target);
                if (r < 0)
                        return log_oom();
        }

        *ret = TAKE_PTR(l);
        return n;
}

static int find_loop_device(const char *backing_file, sd_device **ret) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        int r;

        assert(backing_file);
        assert(ret);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return log_oom();

        r = sd_device_enumerator_add_match_subsystem(e, "block", /* match= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to add subsystem match: %m");

        r = sd_device_enumerator_add_match_property(e, "ID_FS_USAGE", "filesystem");
        if (r < 0)
                return log_error_errno(r, "Failed to add property match: %m");

        r = sd_device_enumerator_add_match_sysname(e, "loop*");
        if (r < 0)
                return log_error_errno(r, "Failed to add sysname match: %m");

        r = sd_device_enumerator_add_match_sysattr(e, "loop/backing_file", /* value= */ NULL, /* match= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to add sysattr match: %m");

        FOREACH_DEVICE(e, dev) {
                const char *s;

                r = sd_device_get_sysattr_value(dev, "loop/backing_file", &s);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Failed to read \"loop/backing_file\" sysattr, ignoring: %m");
                        continue;
                }

                if (inode_same(s, backing_file, 0) <= 0)
                        continue;

                *ret = sd_device_ref(dev);
                return 0;
        }

        return -ENXIO;
}

static int stop_mount(sd_bus *bus, const char *where, const char *suffix) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        _cleanup_free_ char *mount_unit = NULL;
        int r;

        assert(bus);
        assert(where);
        assert(suffix);

        if (!arg_no_block) {
                r = bus_wait_for_jobs_new(bus, &w);
                if (r < 0)
                        return log_error_errno(r, "Could not watch jobs: %m");
        }

        r = unit_name_from_path(where, suffix, &mount_unit);
        if (r < 0)
                return log_error_errno(r, "Failed to make %s unit name from path '%s': %m", suffix + 1, where);

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "StopUnit");
        if (r < 0)
                return bus_log_create_error(r);

        /* Name and mode */
        r = sd_bus_message_append(m, "ss", mount_unit, "fail");
        if (r < 0)
                return bus_log_create_error(r);

        (void) polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

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

                r = bus_wait_for_jobs_one(w, object, arg_quiet ? 0 : BUS_WAIT_JOBS_LOG_ERROR, NULL);
                if (r < 0)
                        return r;
        }

        if (!arg_quiet)
                log_info("Stopped unit %s%s%s for mount point: %s%s%s",
                         ansi_highlight(), mount_unit, ansi_normal(),
                         ansi_highlight(), where, ansi_normal());

        return 0;
}

static int stop_mounts(sd_bus *bus, const char *where) {
        int r;

        assert(bus);
        assert(where);

        if (path_equal(where, "/"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Refusing to unmount root directory.");

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

static int umount_by_device(sd_bus *bus, sd_device *dev) {
        _cleanup_strv_free_ char **list = NULL;
        const char *v;
        int r, ret = 0;

        assert(bus);
        assert(dev);

        if (sd_device_get_property_value(dev, "SYSTEMD_MOUNT_WHERE", &v) >= 0)
                ret = stop_mounts(bus, v);

        r = sd_device_get_devname(dev, &v);
        if (r < 0)
                return r;

        r = find_mount_points_by_source(v, &list);
        if (r < 0)
                return r;

        STRV_FOREACH(l, list)
                RET_GATHER(ret, stop_mounts(bus, *l));

        return ret;
}

static int umount_by_device_node(sd_bus *bus, const char *node) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        const char *v;
        int r;

        assert(bus);
        assert(node);

        r = sd_device_new_from_devname(&dev, node);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from %s: %m", node);

        r = sd_device_get_property_value(dev, "ID_FS_USAGE", &v);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get \"ID_FS_USAGE\" device property: %m");

        if (!streq(v, "filesystem"))
                return log_device_error_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s does not contain a known file system.", node);

        return umount_by_device(bus, dev);
}

static int umount_loop(sd_bus *bus, const char *backing_file) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(backing_file);

        r = find_loop_device(backing_file, &dev);
        if (r < 0)
                return log_error_errno(r, r == -ENXIO ? "File %s is not mounted." : "Can't get loop device for %s: %m", backing_file);

        return umount_by_device(bus, dev);
}

static int action_umount(sd_bus *bus, int argc, char **argv) {
        int r, ret = 0;

        assert(bus);
        assert(argv);
        assert(argc > optind);

        if (arg_transport != BUS_TRANSPORT_LOCAL || !arg_canonicalize) {
                for (int i = optind; i < argc; i++) {
                        _cleanup_free_ char *p = NULL;

                        r = path_simplify_alloc(argv[i], &p);
                        if (r < 0)
                                return r;

                        RET_GATHER(ret, stop_mounts(bus, p));
                }
                return ret;
        }

        for (int i = optind; i < argc; i++) {
                _cleanup_free_ char *u = NULL, *p = NULL;

                u = fstab_node_to_udev_node(argv[i]);
                if (!u)
                        return log_oom();

                _cleanup_close_ int fd = -EBADF;
                r = chase(u, /* root= */ NULL, CHASE_TRIGGER_AUTOFS, &p, &fd);
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to chase path '%s': %m", u));
                        continue;
                }

                struct stat st;
                if (fstat(fd, &st) < 0)
                        return log_error_errno(errno, "Can't stat '%s' (from %s): %m", p, argv[i]);

                r = is_mount_point_at(fd, /* path= */ NULL, /* flags= */ 0);
                fd = safe_close(fd); /* before continuing make sure the dir is not keeping anything busy */
                if (r > 0)
                        RET_GATHER(ret, stop_mounts(bus, p));
                else {
                        /* This can realistically fail on pre-5.8 kernels that do not tell us via statx() if
                         * something is a mount point, hence handle this gracefully, and go by type as we did
                         * in pre-v258 times. */
                        if (r < 0)
                                log_warning_errno(r, "Failed to determine if '%s' is a mount point, ignoring: %m", u);

                        if (S_ISDIR(st.st_mode))
                                r = stop_mounts(bus, p);
                        else if (S_ISBLK(st.st_mode))
                                r = umount_by_device_node(bus, p);
                        else if (S_ISREG(st.st_mode))
                                r = umount_loop(bus, p);
                        else
                                r = log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                    "Unknown file type for unmounting: %s (from %s)",
                                                    p, argv[i]);
                        RET_GATHER(ret, r);
                }
        }

        return ret;
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
        int r;

        if (arg_mount_where)
                return 0;

        if (sd_device_get_property_value(d, "SYSTEMD_MOUNT_WHERE", &v) < 0) {
                _cleanup_free_ char *escaped = NULL, *devname_bn = NULL;
                const char *name;

                name = get_label(d);
                if (!name)
                        (void) device_get_model_string(d, &name);
                if (!name) {
                        const char *dn;

                        if (sd_device_get_devname(d, &dn) < 0)
                                return 0;

                        r = path_extract_filename(dn, &devname_bn);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract file name from '%s': %m", dn);

                        name = devname_bn;
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

static int acquire_mount_where_for_loop_dev(sd_device *dev) {
        _cleanup_strv_free_ char **list = NULL;
        const char *node;
        int r;

        assert(dev);

        if (arg_mount_where)
                return 0;

        r = sd_device_get_devname(dev, &node);
        if (r < 0)
                return r;

        r = find_mount_points_by_source(node, &list);
        if (r < 0)
                return r;
        if (r == 0)
                return log_device_error_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "Can't find mount point of %s. It is expected that %s is already mounted on a place.",
                                              node, node);
        if (r >= 2)
                return log_device_error_errno(dev, SYNTHETIC_ERRNO(EINVAL),
                                              "%s is mounted on %d places. It is expected that %s is mounted on a place.",
                                              node, r, node);

        arg_mount_where = strdup(list[0]);
        if (!arg_mount_where)
                return log_oom();

        log_debug("Discovered where=%s", arg_mount_where);
        return 1;
}

static int acquire_description(sd_device *d) {
        const char *model = NULL, *label;

        if (arg_description)
                return 0;

        (void) device_get_model_string(d, &model);

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
        int r;

        assert(d);

        /* Shortcut this if there's no reason to check it */
        if (arg_action != ACTION_DEFAULT && arg_timeout_idle_set && arg_bind_device >= 0)
                return 0;

        for (;;) {
                if (sd_device_get_sysattr_value(d, "removable", &v) >= 0)
                        break;

                r = sd_device_get_parent(d, &d);
                if (r == -ENODEV)
                        return 0;
                if (r < 0)
                        return r;

                r = device_in_subsystem(d, "block");
                if (r < 0)
                        return r;
                if (r == 0)
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
        int r;

        r = find_loop_device(arg_mount_what, &d);
        if (r == -ENXIO) {
                _cleanup_free_ char *escaped = NULL, *bn = NULL;

                if (arg_mount_where)
                        return 0;

                r = path_extract_filename(arg_mount_what, &bn);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract file name from backing file path '%s': %m", arg_mount_what);

                escaped = xescape(bn, "\\");
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

        } else if (r < 0)
                return log_error_errno(r, "Can't get loop device for %s: %m", arg_mount_what);

        r = acquire_mount_type(d);
        if (r < 0)
                return r;

        r = acquire_mount_options(d);
        if (r < 0)
                return r;

        r = acquire_mount_where_for_loop_dev(d);
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
                                       "Unsupported mount source type for --discover: %s", arg_mount_what);

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

static int list_devices(void) {
        enum {
                COLUMN_NODE,
                COLUMN_DISKSEQ,
                COLUMN_PATH,
                COLUMN_MODEL,
                COLUMN_WWN,
                COLUMN_FSTYPE,
                COLUMN_LABEL,
                COLUMN_UUID,
                _COLUMN_MAX,
        };

        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
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

        table = table_new("node", "diskseq", "path", "model", "wwn", "fstype", "label", "uuid");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        r = table_set_sort(table, (size_t) 0);
        if (r < 0)
                return log_error_errno(r, "Failed to set sort index: %m");

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        FOREACH_DEVICE(e, d) {
                for (unsigned c = 0; c < _COLUMN_MAX; c++) {
                        const char *x = NULL;

                        switch (c) {

                        case COLUMN_NODE:
                                (void) sd_device_get_devname(d, &x);
                                break;

                        case COLUMN_DISKSEQ: {
                                uint64_t ds;

                                r = sd_device_get_diskseq(d, &ds);
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to get diskseq of block device, ignoring: %m");
                                        r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                                } else
                                        r = table_add_cell(table, NULL, TABLE_UINT64, &ds);
                                if (r < 0)
                                        return table_log_add_error(r);

                                continue;
                        }

                        case COLUMN_PATH:
                                (void) sd_device_get_property_value(d, "ID_PATH", &x);
                                break;

                        case COLUMN_MODEL:
                                (void) device_get_model_string(d, &x);
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

                        r = table_add_cell(table, NULL, c == COLUMN_NODE ? TABLE_PATH : TABLE_STRING, x);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        return table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int run(int argc, char* argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_action == ACTION_LIST)
                return list_devices();

        r = bus_connect_transport_systemd(arg_transport, arg_host, arg_runtime_scope, &bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        (void) sd_bus_set_allow_interactive_authorization(bus, arg_ask_password);

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
                r = fsck_exists_for_fstype(arg_mount_type);
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
                return start_transient_mount(bus);

        case ACTION_AUTOMOUNT:
                return start_transient_automount(bus);

        default:
                assert_not_reached();
        }
}

DEFINE_MAIN_FUNCTION(run);
