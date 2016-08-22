/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

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

#include <getopt.h>

#include "libudev.h"
#include "sd-bus.h"

#include "bus-error.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "escape.h"
#include "fstab-util.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "spawn-polkit-agent.h"
#include "strv.h"
#include "udev-util.h"
#include "unit-name.h"
#include "terminal-util.h"

enum {
        ACTION_DEFAULT,
        ACTION_MOUNT,
        ACTION_AUTOMOUNT,
        ACTION_LIST,
} arg_action = ACTION_DEFAULT;

static bool arg_no_block = false;
static bool arg_no_pager = false;
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
static bool arg_fsck = true;

static void polkit_agent_open_if_enabled(void) {

        /* Open the polkit agent as a child process if necessary */
        if (!arg_ask_password)
                return;

        if (arg_transport != BUS_TRANSPORT_LOCAL)
                return;

        polkit_agent_open();
}

static void help(void) {
        printf("%s [OPTIONS...] WHAT [WHERE]\n\n"
               "Establish a mount or auto-mount point transiently.\n\n"
               "  -h --help                       Show this help\n"
               "     --version                    Show package version\n"
               "     --no-block                   Do not wait until operation finished\n"
               "     --no-pager                   Do not pipe output into a pager\n"
               "     --no-ask-password            Do not prompt for password\n"
               "  -q --quiet                      Suppress information messages during runtime\n"
               "     --user                       Run as user unit\n"
               "  -H --host=[USER@]HOST           Operate on remote host\n"
               "  -M --machine=CONTAINER          Operate on local container\n"
               "     --discover                   Discover mount device metadata\n"
               "  -t --type=TYPE                  File system type\n"
               "  -o --options=OPTIONS            Mount options\n"
               "     --fsck=no                    Don't run file system check before mount\n"
               "     --description=TEXT           Description for unit\n"
               "  -p --property=NAME=VALUE        Set mount unit property\n"
               "  -A --automount=BOOL             Create an auto-mount point\n"
               "     --timeout-idle-sec=SEC       Specify automount idle timeout\n"
               "     --automount-property=NAME=VALUE\n"
               "                                  Set automount unit property\n"
               "     --bind-device                Bind automount unit to device\n"
               "     --list                       List mountable block devices\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_BLOCK,
                ARG_NO_PAGER,
                ARG_NO_ASK_PASSWORD,
                ARG_USER,
                ARG_SYSTEM,
                ARG_DISCOVER,
                ARG_MOUNT_TYPE,
                ARG_MOUNT_OPTIONS,
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
                { "no-ask-password",    no_argument,       NULL, ARG_NO_ASK_PASSWORD    },
                { "quiet",              no_argument,       NULL, 'q'                    },
                { "user",               no_argument,       NULL, ARG_USER               },
                { "system",             no_argument,       NULL, ARG_SYSTEM             },
                { "host",               required_argument, NULL, 'H'                    },
                { "machine",            required_argument, NULL, 'M'                    },
                { "discover",           no_argument,       NULL, ARG_DISCOVER           },
                { "type",               required_argument, NULL, 't'                    },
                { "options",            required_argument, NULL, 'o'                    },
                { "description",        required_argument, NULL, ARG_DESCRIPTION        },
                { "property",           required_argument, NULL, 'p'                    },
                { "automount",          required_argument, NULL, ARG_AUTOMOUNT          },
                { "timeout-idle-sec",   required_argument, NULL, ARG_TIMEOUT_IDLE       },
                { "automount-property", required_argument, NULL, ARG_AUTOMOUNT_PROPERTY },
                { "bind-device",        no_argument,       NULL, ARG_BIND_DEVICE        },
                { "list",               no_argument,       NULL, ARG_LIST               },
                {},
        };

        int r, c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hqH:M:t:o:p:A", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
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
                        if (free_and_strdup(&arg_mount_type, optarg) < 0)
                                return log_oom();
                        break;

                case 'o':
                        if (free_and_strdup(&arg_mount_options, optarg) < 0)
                                return log_oom();
                        break;

                case ARG_FSCK:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --fsck= argument: %s", optarg);

                        arg_fsck = r;
                        break;

                case ARG_DESCRIPTION:
                        if (free_and_strdup(&arg_description, optarg) < 0)
                                return log_oom();
                        break;

                case 'p':
                        if (strv_extend(&arg_property, optarg) < 0)
                                return log_oom();

                        break;

                case 'A':
                        arg_action = ACTION_AUTOMOUNT;
                        break;

                case ARG_AUTOMOUNT:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "--automount= expects a valid boolean parameter: %s", optarg);

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

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (arg_user && arg_transport != BUS_TRANSPORT_LOCAL) {
                log_error("Execution in user context is not supported on non-local systems.");
                return -EINVAL;
        }

        if (arg_action == ACTION_LIST) {
                if (optind < argc) {
                        log_error("Too many arguments.");
                        return -EINVAL;
                }

                if (arg_transport != BUS_TRANSPORT_LOCAL) {
                        log_error("Listing devices only supported locally.");
                        return -EOPNOTSUPP;
                }
        } else {
                if (optind >= argc) {
                        log_error("At least one argument required.");
                        return -EINVAL;
                }

                if (argc > optind+2) {
                        log_error("At most two arguments required.");
                        return -EINVAL;
                }

                arg_mount_what = fstab_node_to_udev_node(argv[optind]);
                if (!arg_mount_what)
                        return log_oom();

                if (argc > optind+1) {
                        r = path_make_absolute_cwd(argv[optind+1], &arg_mount_where);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make path absolute: %m");
                } else
                        arg_discover = true;

                if (arg_discover && arg_transport != BUS_TRANSPORT_LOCAL) {
                        log_error("Automatic mount location discovery is only supported locally.");
                        return -EOPNOTSUPP;
                }
        }

        return 1;
}

static int transient_unit_set_properties(sd_bus_message *m, char **properties) {
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

        r = bus_append_unit_property_assignment_many(m, properties);
        if (r < 0)
                return r;

        return 0;
}

static int transient_mount_set_properties(sd_bus_message *m) {
        int r;

        assert(m);

        r = transient_unit_set_properties(m, arg_property);
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

        if (arg_mount_options) {
                r = sd_bus_message_append(m, "(sv)", "Options", "s", arg_mount_options);
                if (r < 0)
                        return r;
        }

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

        r = transient_unit_set_properties(m, arg_automount_property);
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

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
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

        polkit_agent_open_if_enabled();

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

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "StartTransientUnit");
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

        polkit_agent_open_if_enabled();

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

static int acquire_mount_type(struct udev_device *d) {
        const char *v;

        assert(d);

        if (arg_mount_type)
                return 0;

        v = udev_device_get_property_value(d, "ID_FS_TYPE");
        if (isempty(v))
                return 0;

        arg_mount_type = strdup(v);
        if (!arg_mount_type)
                return log_oom();

        log_debug("Discovered type=%s", arg_mount_type);
        return 1;
}

static int acquire_mount_options(struct udev_device *d) {
        const char *v;

        if (arg_mount_options)
                return 0;

        v = udev_device_get_property_value(d, "SYSTEMD_MOUNT_OPTIONS");
        if (isempty(v))
                return 0;

        arg_mount_options = strdup(v);
        if (!arg_mount_options)
                return log_oom();

        log_debug("Discovered options=%s", arg_mount_options);
        return 1;
}

static const char *get_model(struct udev_device *d) {
        const char *model;

        assert(d);

        model = udev_device_get_property_value(d, "ID_MODEL_FROM_DATABASE");
        if (model)
                return model;

        return udev_device_get_property_value(d, "ID_MODEL");
}

static const char* get_label(struct udev_device *d) {
        const char *label;

        assert(d);

        label = udev_device_get_property_value(d, "ID_FS_LABEL");
        if (label)
                return label;

        return udev_device_get_property_value(d, "ID_PART_ENTRY_NAME");
}

static int acquire_mount_where(struct udev_device *d) {
        const char *v;

        if (arg_mount_where)
                return 0;

        v = udev_device_get_property_value(d, "SYSTEMD_MOUNT_WHERE");
        if (isempty(v)) {
                _cleanup_free_ char *escaped = NULL;
                const char *name;

                name = get_label(d);
                if (!name)
                        name = get_model(d);
                if (!name) {
                        const char *dn;

                        dn = udev_device_get_devnode(d);
                        if (!dn)
                                return 0;

                        name = basename(dn);
                }

                escaped = xescape(name, "\\");
                if (!filename_is_valid(escaped))
                        return 0;

                arg_mount_where = strjoin("/run/media/system/", escaped, NULL);
        } else
                arg_mount_where = strdup(v);

        if (!arg_mount_where)
                return log_oom();

        log_debug("Discovered where=%s", arg_mount_where);
        return 1;
}

static int acquire_description(struct udev_device *d) {
        const char *model, *label;

        if (arg_description)
                return 0;

        model = get_model(d);

        label = get_label(d);
        if (!label)
                label = udev_device_get_property_value(d, "ID_PART_ENTRY_NUMBER");

        if (model && label)
                arg_description = strjoin(model, " ", label, NULL);
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

static int acquire_removable(struct udev_device *d) {
        const char *v;

        /* Shortcut this if there's no reason to check it */
        if (arg_action != ACTION_DEFAULT && arg_timeout_idle_set && arg_bind_device >= 0)
                return 0;

        for (;;) {
                v = udev_device_get_sysattr_value(d, "removable");
                if (v)
                        break;

                d = udev_device_get_parent(d);
                if (!d)
                        return 0;

                if (!streq_ptr(udev_device_get_subsystem(d), "block"))
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

static int discover_device(void) {
        _cleanup_udev_device_unref_ struct udev_device *d = NULL;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        struct stat st;
        const char *v;
        int r;

        if (!arg_discover)
                return 0;

        if (!is_device_path(arg_mount_what)) {
                log_error("Discovery only supported for block devices, don't know what to do.");
                return -EINVAL;
        }

        if (stat(arg_mount_what, &st) < 0)
                return log_error_errno(errno, "Can't stat %s: %m", arg_mount_what);

        if (!S_ISBLK(st.st_mode)) {
                log_error("Path %s is not a block device, don't know what to do.", arg_mount_what);
                return -ENOTBLK;
        }

        udev = udev_new();
        if (!udev)
                return log_oom();

        d = udev_device_new_from_devnum(udev, 'b', st.st_rdev);
        if (!d)
                return log_oom();

        v = udev_device_get_property_value(d, "ID_FS_USAGE");
        if (!streq_ptr(v, "filesystem")) {
                log_error("%s does not contain a file system.", arg_mount_what);
                return -EINVAL;
        }

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

struct item {
        char* columns[_COLUMN_MAX];
};

static int compare_item(const void *a, const void *b) {
        const struct item *x = a, *y = b;

        if (x->columns[COLUMN_NODE] == y->columns[COLUMN_NODE])
                return 0;
        if (!x->columns[COLUMN_NODE])
                return 1;
        if (!y->columns[COLUMN_NODE])
                return -1;

        return path_compare(x->columns[COLUMN_NODE], y->columns[COLUMN_NODE]);
}

static int list_devices(void) {

        static const char * const titles[_COLUMN_MAX] = {
                [COLUMN_NODE] = "NODE",
                [COLUMN_PATH] = "PATH",
                [COLUMN_MODEL] = "MODEL",
                [COLUMN_WWN] = "WWN",
                [COLUMN_FSTYPE] = "TYPE",
                [COLUMN_LABEL] = "LABEL",
                [COLUMN_UUID] = "UUID"
        };

        _cleanup_udev_enumerate_unref_ struct udev_enumerate *e = NULL;
        _cleanup_udev_unref_ struct udev *udev = NULL;
        struct udev_list_entry *item = NULL, *first = NULL;
        size_t n_allocated = 0, n = 0, i;
        size_t column_width[_COLUMN_MAX];
        struct item *items = NULL;
        unsigned c;
        int r;

        for (c = 0; c < _COLUMN_MAX; c++)
                column_width[c] = strlen(titles[c]);

        udev = udev_new();
        if (!udev)
                return log_oom();

        e = udev_enumerate_new(udev);
        if (!e)
                return log_oom();

        r = udev_enumerate_add_match_subsystem(e, "block");
        if (r < 0)
                return log_error_errno(r, "Failed to add block match: %m");

        r = udev_enumerate_add_match_property(e, "ID_FS_USAGE", "filesystem");
        if (r < 0)
                return log_error_errno(r, "Failed to add property match: %m");

        r = udev_enumerate_scan_devices(e);
        if (r < 0)
                return log_error_errno(r, "Failed to scan devices: %m");

        first = udev_enumerate_get_list_entry(e);
        udev_list_entry_foreach(item, first) {
                _cleanup_udev_device_unref_ struct udev_device *d;
                struct item *j;

                d = udev_device_new_from_syspath(udev, udev_list_entry_get_name(item));
                if (!d) {
                        r = log_oom();
                        goto finish;
                }

                if (!GREEDY_REALLOC0(items, n_allocated, n+1)) {
                        r = log_oom();
                        goto finish;
                }

                j = items + n++;

                for (c = 0; c < _COLUMN_MAX; c++) {
                        const char *x;
                        size_t k;

                        switch (c) {

                        case COLUMN_NODE:
                                x = udev_device_get_devnode(d);
                                break;

                        case COLUMN_PATH:
                                x = udev_device_get_property_value(d, "ID_PATH");
                                break;

                        case COLUMN_MODEL:
                                x = get_model(d);
                                break;

                        case COLUMN_WWN:
                                x = udev_device_get_property_value(d, "ID_WWN");
                                break;

                        case COLUMN_FSTYPE:
                                x = udev_device_get_property_value(d, "ID_FS_TYPE");
                                break;

                        case COLUMN_LABEL:
                                x = get_label(d);
                                break;

                        case COLUMN_UUID:
                                x = udev_device_get_property_value(d, "ID_FS_UUID");
                                break;
                        }

                        if (isempty(x))
                                continue;

                        j->columns[c] = strdup(x);
                        if (!j->columns[c]) {
                                r = log_oom();
                                goto finish;
                        }

                        k = strlen(x);
                        if (k > column_width[c])
                                column_width[c] = k;
                }
        }

        if (n == 0) {
                log_info("No devices found.");
                goto finish;
        }

        qsort_safe(items, n, sizeof(struct item), compare_item);

        pager_open(arg_no_pager, false);

        fputs(ansi_underline(), stdout);
        for (c = 0; c < _COLUMN_MAX; c++) {
                if (c > 0)
                        fputc(' ', stdout);

                printf("%-*s", (int) column_width[c], titles[c]);
        }
        fputs(ansi_normal(), stdout);
        fputc('\n', stdout);

        for (i = 0; i < n; i++) {
                for (c = 0; c < _COLUMN_MAX; c++) {
                        if (c > 0)
                                fputc(' ', stdout);

                        printf("%-*s", (int) column_width[c], strna(items[i].columns[c]));
                }
                fputc('\n', stdout);
        }

        r = 0;

finish:
        for (i = 0; i < n; i++)
                for (c = 0; c < _COLUMN_MAX; c++)
                        free(items[i].columns[c]);

        free(items);
        return r;
}

int main(int argc, char* argv[]) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (arg_action == ACTION_LIST) {
                r = list_devices();
                goto finish;
        }

        r = discover_device();
        if (r < 0)
                goto finish;
        if (!arg_mount_where) {
                log_error("Can't figure out where to mount %s.", arg_mount_what);
                r = -EINVAL;
                goto finish;
        }

        path_kill_slashes(arg_mount_where);

        if (path_equal(arg_mount_where, "/")) {
                log_error("Refusing to operate on root directory.");
                r = -EINVAL;
                goto finish;
        }

        if (!path_is_safe(arg_mount_where)) {
                log_error("Path is contains unsafe components.");
                r = -EINVAL;
                goto finish;
        }

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

        r = bus_connect_transport_systemd(arg_transport, arg_host, arg_user, &bus);
        if (r < 0) {
                log_error_errno(r, "Failed to create bus connection: %m");
                goto finish;
        }

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

finish:
        bus = sd_bus_flush_close_unref(bus);

        pager_close();

        free(arg_mount_what);
        free(arg_mount_where);
        free(arg_mount_type);
        free(arg_mount_options);
        free(arg_description);
        strv_free(arg_property);
        strv_free(arg_automount_property);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
