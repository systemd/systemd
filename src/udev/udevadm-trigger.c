/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>

#include "sd-device.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "device-enumerator-private.h"
#include "device-private.h"
#include "device-util.h"
#include "format-table.h"
#include "help-util.h"
#include "id128-util.h"
#include "options.h"
#include "set.h"
#include "static-destruct.h"
#include "string-table.h"
#include "strv.h"
#include "time-util.h"
#include "udevadm.h"
#include "udevadm-util.h"
#include "virt.h"

typedef enum {
        SCAN_TYPE_DEVICES,
        SCAN_TYPE_SUBSYSTEMS,
        SCAN_TYPE_ALL,
        _SCAN_TYPE_MAX,
        _SCAN_TYPE_INVALID = -EINVAL,
} ScanType;

static bool arg_verbose = false;
static bool arg_dry_run = false;
static bool arg_quiet = false;
static bool arg_uuid = false;
static bool arg_settle = false;
static ScanType arg_scan_type = SCAN_TYPE_DEVICES;
static sd_device_action_t arg_action = SD_DEVICE_CHANGE;
static char **arg_devices = NULL;
static char **arg_attr_match = NULL;
static char **arg_attr_nomatch = NULL;
static char **arg_name_match = NULL;
static char **arg_parent_match = NULL;
static char **arg_property_match = NULL;
static char **arg_subsystem_match = NULL;
static char **arg_subsystem_nomatch = NULL;
static char **arg_sysname_match = NULL;
static char **arg_tag_match = NULL;
static char **arg_prioritized_subsystems = NULL;
static int arg_initialized_match = -1;
static bool arg_include_parents = false;
static bool arg_ping = false;
static usec_t arg_ping_timeout_usec = 5 * USEC_PER_SEC;

STATIC_DESTRUCTOR_REGISTER(arg_devices, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_attr_match, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_attr_nomatch, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_name_match, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_parent_match, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_property_match, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_subsystem_match, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_subsystem_nomatch, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_sysname_match, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_tag_match, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_prioritized_subsystems, strv_freep);

static const char *scan_type_table[_SCAN_TYPE_MAX] = {
        [SCAN_TYPE_DEVICES]    = "devices",
        [SCAN_TYPE_SUBSYSTEMS] = "subsystems",
        [SCAN_TYPE_ALL]        = "all",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(scan_type, ScanType);

static int exec_list(
                sd_device_enumerator *e,
                sd_device_action_t action,
                Set *settle_ids) {

        const char *action_str = device_action_to_string(action);
        int r, ret = 0;

        assert(e);

        sd_device *d;
        FOREACH_DEVICE_AND_SUBSYSTEM(e, d) {

                const char *syspath;
                r = sd_device_get_syspath(d, &syspath);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get syspath of enumerated devices, ignoring: %m");
                        continue;
                }

                if (arg_verbose)
                        printf("%s\n", syspath);

                if (arg_dry_run)
                        continue;

                sd_id128_t id;
                r = sd_device_trigger_with_uuid(d, action, &id);
                if (r < 0) {
                        /* ENOENT may be returned when a device does not have /uevent or is already
                         * removed. Hence, this is logged at debug level and ignored.
                         *
                         * ENODEV may be returned by some buggy device drivers e.g. /sys/devices/vio.
                         * See,
                         * https://github.com/systemd/systemd/issues/13652#issuecomment-535129791 and
                         * https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1845319.
                         * So, this error is ignored, but logged at warning level to encourage people to
                         * fix the driver.
                         *
                         * EROFS is returned when /sys is read only. In that case, all subsequent
                         * writes will also fail, hence return immediately.
                         *
                         * EACCES or EPERM may be returned when this is invoked by non-privileged user.
                         * We do NOT return immediately, but continue operation and propagate the error.
                         * Why? Some device can be owned by a user, e.g., network devices configured in
                         * a network namespace. See, https://github.com/systemd/systemd/pull/18559 and
                         * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ebb4a4bf76f164457184a3f43ebc1552416bc823
                         *
                         * All other errors are logged at error level, but let's continue the operation,
                         * and propagate the error.
                         */

                        bool ignore = IN_SET(r, -ENOENT, -ENODEV);
                        int level =
                                arg_quiet ? LOG_DEBUG :
                                r == -ENOENT ? LOG_DEBUG :
                                r == -ENODEV ? LOG_WARNING : LOG_ERR;

                        log_device_full_errno(d, level, r,
                                              "Failed to write '%s' to '%s/uevent'%s: %m",
                                              action_str, syspath, ignore ? ", ignoring" : "");

                        if (r == -EROFS)
                                return r;
                        if (!ignore)
                                RET_GATHER(ret, r);
                        continue;
                } else
                        log_device_debug(d, "Triggered device with action '%s'.", action_str);

                /* If the user asked for it, write event UUID to stdout */
                if (arg_uuid)
                        printf(SD_ID128_UUID_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(id));

                if (settle_ids) {
                        sd_id128_t *dup = newdup(sd_id128_t, &id, 1);
                        if (!dup)
                                return log_oom();

                        r = set_consume(settle_ids, dup);
                        if (r < 0)
                                return log_oom();
                }
        }

        return ret;
}

static int device_monitor_handler(sd_device_monitor *m, sd_device *dev, void *userdata) {
        Set *settle_ids = ASSERT_PTR(userdata);
        int r;

        assert(dev);

        sd_id128_t id;
        r = sd_device_get_trigger_uuid(dev, &id);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Got uevent without UUID, ignoring: %m");
                return 0;
        }

        _cleanup_free_ sd_id128_t *saved = set_remove(settle_ids, &id);
        if (!saved) {
                log_device_debug(dev, "Got uevent with unexpected UUID, ignoring.");
                return 0;
        }

        if (arg_verbose) {
                const char *syspath;

                r = sd_device_get_syspath(dev, &syspath);
                if (r < 0)
                        log_device_debug_errno(dev, r, "Failed to get syspath of device event, ignoring: %m");
                else
                        printf("settle %s\n", syspath);
        }

        if (arg_uuid)
                printf("settle " SD_ID128_UUID_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(id));

        if (set_isempty(settle_ids))
                return sd_event_exit(sd_device_monitor_get_event(m), 0);

        return 0;
}

static int add_device_match(sd_device_enumerator *e, const char *s, const char *prefix) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(e);
        assert(s);

        r = find_device(s, prefix, &dev);
        if (r < 0)
                return log_error_errno(r, "Failed to open the device '%s': %m", s);

        r = device_enumerator_add_match_parent_incremental(e, dev);
        if (r < 0)
                return log_error_errno(r, "Failed to add parent match '%s': %m", s);

        return 0;
}

static int setup_matches(sd_device_enumerator *e) {
        int r;

        assert(e);

        STRV_FOREACH(d, arg_devices) {
                r = add_device_match(e, *d, /* prefix= */ NULL);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(n, arg_name_match) {
                r = add_device_match(e, *n, "/dev/");
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(p, arg_parent_match) {
                r = add_device_match(e, *p, "/sys/");
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(s, arg_subsystem_match) {
                r = sd_device_enumerator_add_match_subsystem(e, *s, /* match= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to add subsystem match '%s': %m", *s);
        }

        STRV_FOREACH(s, arg_subsystem_nomatch) {
                r = sd_device_enumerator_add_match_subsystem(e, *s, /* match= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to add negative subsystem match '%s': %m", *s);
        }

        STRV_FOREACH(a, arg_attr_match) {
                _cleanup_free_ char *k = NULL, *v = NULL;

                r = parse_key_value_argument(*a, /* require_value= */ false, &k, &v);
                if (r < 0)
                        return r;

                r = sd_device_enumerator_add_match_sysattr(e, k, v, /* match= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to add sysattr match '%s=%s': %m", k, v);
        }

        STRV_FOREACH(a, arg_attr_nomatch) {
                _cleanup_free_ char *k = NULL, *v = NULL;

                r = parse_key_value_argument(*a, /* require_value= */ false, &k, &v);
                if (r < 0)
                        return r;

                r = sd_device_enumerator_add_match_sysattr(e, k, v, /* match= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to add negative sysattr match '%s=%s': %m", k, v);
        }

        STRV_FOREACH(p, arg_property_match) {
                _cleanup_free_ char *k = NULL, *v = NULL;

                r = parse_key_value_argument(*p, /* require_value= */ true, &k, &v);
                if (r < 0)
                        return r;

                r = sd_device_enumerator_add_match_property(e, k, v);
                if (r < 0)
                        return log_error_errno(r, "Failed to add property match '%s=%s': %m", k, v);
        }

        STRV_FOREACH(t, arg_tag_match) {
                r = sd_device_enumerator_add_match_tag(e, *t);
                if (r < 0)
                        return log_error_errno(r, "Failed to add tag match '%s': %m", *t);
        }

        STRV_FOREACH(s, arg_sysname_match) {
                r = sd_device_enumerator_add_match_sysname(e, *s);
                if (r < 0)
                        return log_error_errno(r, "Failed to add sysname match '%s': %m", *s);
        }

        STRV_FOREACH(p, arg_prioritized_subsystems) {
                r = device_enumerator_add_prioritized_subsystem(e, *p);
                if (r < 0)
                        return log_error_errno(r, "Failed to add prioritized subsystem '%s': %m", *p);
        }

        if (arg_initialized_match != -1) {
                r = device_enumerator_add_match_is_initialized(e, arg_initialized_match);
                if (r < 0)
                        return log_error_errno(r, "Failed to set initialized filter: %m");
        }

        if (arg_include_parents) {
                r = sd_device_enumerator_add_all_parents(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to always include all parents: %m");
        }

        return 0;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-trigger", &options);
        if (r < 0)
                return r;

        help_cmdline("trigger [OPTIONS] DEVPATH");
        help_abstract("Request events from the kernel.");
        help_section("Options:");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("udevadm", "8");
        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        int r;

        assert(argc >= 0);
        assert(argv);

        OptionParser opts = { argc, argv, .namespace = "udevadm-trigger" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("udevadm-trigger"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION('V', "version", NULL, "Show package version"):
                        return print_version();

                OPTION('v', "verbose", NULL, "Print the list of devices while running"):
                        arg_verbose = true;
                        break;

                OPTION('n', "dry-run", NULL, "Do not actually trigger the events"):
                        arg_dry_run = true;
                        break;

                OPTION('q', "quiet", NULL, "Suppress error logging in triggering events"):
                        arg_quiet = true;
                        break;

                OPTION('t', "type", "TYPE", "Type of sysfs events to trigger:"): {}
                OPTION_HELP_VERBATIM("        devices",    "- devices (default)"): {}
                OPTION_HELP_VERBATIM("        subsystems", "- subsystems and drivers"): {}
                OPTION_HELP_VERBATIM("        all",        "- devices, subsystems, and drivers"):
                        arg_scan_type = scan_type_from_string(opts.arg);
                        if (arg_scan_type < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown type --type=%s", opts.arg);
                        break;

                OPTION('c', "action", "ACTION|help", "Event action value, default is \"change\""):
                        r = parse_device_action(opts.arg, &arg_action);
                        if (r <= 0)
                                return r;
                        break;

                OPTION('s', "subsystem-match", "SUBSYSTEM",
                       "Trigger devices from a matching subsystem"):
                        r = strv_extend(&arg_subsystem_match, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('S', "subsystem-nomatch", "SUBSYSTEM",
                       "Exclude devices from a matching subsystem"):
                        r = strv_extend(&arg_subsystem_nomatch, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('a', "attr-match", "FILE[=VALUE]",
                       "Trigger devices with a matching attribute"):
                        r = strv_extend(&arg_attr_match, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('A', "attr-nomatch", "FILE[=VALUE]",
                       "Exclude devices with a matching attribute"):
                        r = strv_extend(&arg_attr_nomatch, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('p', "property-match", "KEY=VALUE",
                       "Trigger devices with a matching property"):
                        r = strv_extend(&arg_property_match, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('g', "tag-match", "TAG", "Trigger devices with a matching tag"):
                        r = strv_extend(&arg_tag_match, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('y', "sysname-match", "NAME", "Trigger devices with this /sys path"):
                        r = strv_extend(&arg_sysname_match, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION_LONG("name-match", "NAME", "Trigger devices with this /dev name"):
                        r = strv_extend(&arg_name_match, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION('b', "parent-match", "NAME", "Trigger devices with that parent device"):
                        r = strv_extend(&arg_parent_match, opts.arg);
                        if (r < 0)
                                return log_oom();
                        break;

                OPTION_LONG("include-parents", NULL, "Trigger parent devices of found devices"):
                        arg_include_parents = true;
                        break;

                OPTION_LONG("initialized-match", NULL,
                            "Trigger devices that are already initialized"):
                        arg_initialized_match = MATCH_INITIALIZED_YES;
                        break;

                OPTION_LONG("initialized-nomatch", NULL,
                            "Trigger devices that are not initialized yet"):
                        arg_initialized_match = MATCH_INITIALIZED_NO;
                        break;

                OPTION('w', "settle", NULL, "Wait for the triggered events to complete"):
                        arg_settle = true;
                        break;

                OPTION_LONG_FLAGS(OPTION_OPTIONAL_ARG, "wait-daemon", "SECONDS",
                                  "Wait for udevd daemon to be initialized before triggering uevents"):
                        arg_ping = true;
                        if (opts.arg) {
                                r = parse_sec(opts.arg, &arg_ping_timeout_usec);
                                if (r < 0)
                                        log_error_errno(r, "Failed to parse timeout value '%s', ignoring: %m", opts.arg);
                        }
                        break;

                OPTION_LONG("uuid", NULL, "Print synthetic uevent UUID"):
                        arg_uuid = true;
                        break;

                OPTION_LONG("prioritized-subsystem", "SUBSYSTEM[,SUBSYSTEM…]",
                            "Trigger devices from a matching subsystem first"):
                        r = strv_split_and_extend(&arg_prioritized_subsystems, opts.arg, ",", /* filter_duplicates= */ false);
                        if (r < 0)
                                return log_oom();
                        break;
                }

        r = strv_extend_strv(&arg_devices, option_parser_get_args(&opts), /* filter_duplicates= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to build argument list: %m");

        return 1;
}

int verb_trigger_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_set_free_ Set *settle_ids = NULL;
        int r;

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = setup_matches(e);
        if (r < 0)
                return r;

        if (arg_ping) {
                r = udev_ping(arg_ping_timeout_usec, /* ignore_connection_failure= */ false);
                if (r < 0)
                        return r;
                assert(r > 0);
        }

        if (arg_settle) {
                r = sd_event_default(&event);
                if (r < 0)
                        return log_error_errno(r, "Failed to get default event: %m");

                r = sd_device_monitor_new(&m);
                if (r < 0)
                        return log_error_errno(r, "Failed to create device monitor object: %m");

                r = sd_device_monitor_attach_event(m, event);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach event to device monitor: %m");

                settle_ids = set_new(&id128_hash_ops_free);
                if (!settle_ids)
                        return log_oom();

                r = sd_device_monitor_start(m, device_monitor_handler, settle_ids);
                if (r < 0)
                        return log_error_errno(r, "Failed to start device monitor: %m");
        }

        switch (arg_scan_type) {
        case SCAN_TYPE_SUBSYSTEMS:
                r = device_enumerator_scan_subsystems(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan subsystems: %m");
                break;
        case SCAN_TYPE_DEVICES:
                r = device_enumerator_scan_devices(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan devices: %m");
                break;
        case SCAN_TYPE_ALL:
                r = device_enumerator_scan_devices_and_subsystems(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan devices and subsystems: %m");
                break;
        default:
                assert_not_reached();
        }

        r = exec_list(e, arg_action, settle_ids);
        if (r < 0)
                return r;

        if (set_isempty(settle_ids))
                return 0;

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}
