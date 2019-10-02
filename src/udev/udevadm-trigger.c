/* SPDX-License-Identifier: GPL-2.0+ */

#include <errno.h>
#include <getopt.h>

#include "sd-device.h"
#include "sd-event.h"

#include "device-enumerator-private.h"
#include "device-private.h"
#include "fd-util.h"
#include "fileio.h"
#include "id128-util.h"
#include "path-util.h"
#include "process-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "udevadm.h"
#include "udevadm-util.h"
#include "udev-ctrl.h"
#include "virt.h"

struct trigger_handle {
        const char *action;
        char synth_uuid[SD_ID128_UUID_STRING_MAX];
        Set *settle_set;
};

static bool arg_verbose = false;
static bool arg_dry_run = false;

static int exec_list(sd_device_enumerator *e, struct trigger_handle *trigger_handle) {
        _cleanup_free_ char *trigger = NULL;
        sd_device *d;
        int r, ret = 0;

        trigger = strjoin(trigger_handle->action, " ", trigger_handle->synth_uuid, " UDEVTRIGGER=1");
        if (!trigger)
                return log_oom();

        FOREACH_DEVICE_AND_SUBSYSTEM(e, d) {
                _cleanup_free_ char *filename = NULL;
                _cleanup_free_ char *key = NULL;
                const char *syspath;

                if (sd_device_get_syspath(d, &syspath) < 0)
                        continue;

                if (arg_verbose)
                        printf("%s\n", syspath);
                if (arg_dry_run)
                        continue;

                filename = path_join(syspath, "uevent");
                if (!filename)
                        return log_oom();

                r = write_string_file(filename, trigger, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0) {
                        bool ignore = IN_SET(r, -ENOENT, -EACCES, -ENODEV);

                        log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r,
                                       "Failed to write '%s' to '%s': %m", trigger, filename);
                        if (ret == 0 && !ignore)
                                ret = r;
                        continue;
                }

                if (trigger_handle->settle_set) {
                        key = strjoin(trigger_handle->synth_uuid, syspath);
                        if (!key)
                                return log_oom();

                        r = set_put_strdup(trigger_handle->settle_set, key);
                        if (r < 0)
                                return log_oom();
                }
        }

        return ret;
}

static int device_monitor_handler(sd_device_monitor *m, sd_device *dev, void *userdata) {
        _cleanup_free_ char *key = NULL;
        _cleanup_free_ char *val = NULL;
        struct trigger_handle *trigger_handle = userdata;
        const char *syspath, *synth_uuid_str;

        assert(dev);
        assert(trigger_handle->settle_set);

        if (sd_device_get_syspath(dev, &syspath) < 0)
                return 0;

        if (sd_device_get_property_value(dev, "SYNTH_UUID", &synth_uuid_str) < 0)
                return 0;

        key = strjoin(synth_uuid_str, syspath);
        if (!key)
                return log_oom();

        if (arg_verbose)
                printf("settle %s\n", key);

        val = set_remove(trigger_handle->settle_set, key);
        if (!val)
                log_debug("Got epoll event on uuid/syspath %s not present in uuid/syspath set", key);

        if (set_isempty(trigger_handle->settle_set))
                return sd_event_exit(sd_device_monitor_get_event(m), 0);

        return 0;
}

static char* keyval(const char *str, const char **key, const char **val) {
        char *buf, *pos;

        buf = strdup(str);
        if (!buf)
                return NULL;

        pos = strchr(buf, '=');
        if (pos) {
                pos[0] = 0;
                pos++;
        }

        *key = buf;
        *val = pos;

        return buf;
}

static int help(void) {
        printf("%s trigger [OPTIONS] DEVPATH\n\n"
               "Request events from the kernel.\n\n"
               "  -h --help                         Show this help\n"
               "  -V --version                      Show package version\n"
               "  -v --verbose                      Print the list of devices while running\n"
               "  -n --dry-run                      Do not actually trigger the events\n"
               "  -t --type=                        Type of events to trigger\n"
               "          devices                     sysfs devices (default)\n"
               "          subsystems                  sysfs subsystems and drivers\n"
               "  -c --action=ACTION|help           Event action value, default is \"change\"\n"
               "  -s --subsystem-match=SUBSYSTEM    Trigger devices from a matching subsystem\n"
               "  -S --subsystem-nomatch=SUBSYSTEM  Exclude devices from a matching subsystem\n"
               "  -a --attr-match=FILE[=VALUE]      Trigger devices with a matching attribute\n"
               "  -A --attr-nomatch=FILE[=VALUE]    Exclude devices with a matching attribute\n"
               "  -p --property-match=KEY=VALUE     Trigger devices with a matching property\n"
               "  -g --tag-match=KEY=VALUE          Trigger devices with a matching property\n"
               "  -y --sysname-match=NAME           Trigger devices with this /sys path\n"
               "     --name-match=NAME              Trigger devices with this /dev name\n"
               "  -b --parent-match=NAME            Trigger devices with that parent device\n"
               "  -u --synth-uuid=UUID              Use UUID for SYNTH_UUID key in triggered events\n"
               "  -w --settle                       Wait for the triggered events to complete\n"
               "     --wait-daemon[=SECONDS]        Wait for udevd daemon to be initialized\n"
               "                                    before triggering uevents\n"
               , program_invocation_short_name);

        return 0;
}

int trigger_main(int argc, char *argv[], void *userdata) {
        enum {
                ARG_NAME = 0x100,
                ARG_PING,
        };

        static const struct option options[] = {
                { "verbose",           no_argument,       NULL, 'v'      },
                { "dry-run",           no_argument,       NULL, 'n'      },
                { "type",              required_argument, NULL, 't'      },
                { "action",            required_argument, NULL, 'c'      },
                { "subsystem-match",   required_argument, NULL, 's'      },
                { "subsystem-nomatch", required_argument, NULL, 'S'      },
                { "attr-match",        required_argument, NULL, 'a'      },
                { "attr-nomatch",      required_argument, NULL, 'A'      },
                { "property-match",    required_argument, NULL, 'p'      },
                { "tag-match",         required_argument, NULL, 'g'      },
                { "sysname-match",     required_argument, NULL, 'y'      },
                { "name-match",        required_argument, NULL, ARG_NAME },
                { "parent-match",      required_argument, NULL, 'b'      },
                { "settle",            no_argument,       NULL, 'w'      },
                { "synth-uuid",        required_argument, NULL, 'u'      },
                { "wait-daemon",       optional_argument, NULL, ARG_PING },
                { "version",           no_argument,       NULL, 'V'      },
                { "help",              no_argument,       NULL, 'h'      },
                {}
        };
        enum {
                TYPE_DEVICES,
                TYPE_SUBSYSTEMS,
        } device_type = TYPE_DEVICES;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_set_free_free_ Set *settle_set = NULL;
        struct trigger_handle trigger_handle = {.action = device_action_to_string(DEVICE_ACTION_CHANGE),
                                                .synth_uuid[0] = '\0',
                                                .settle_set = NULL};
        usec_t ping_timeout_usec = 5 * USEC_PER_SEC;
        bool settle = false, ping = false;
        sd_id128_t id = SD_ID128_NULL;
        int c, r;

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return 0;
        }

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        while ((c = getopt_long(argc, argv, "vnt:c:s:S:a:A:p:g:y:b:u:wVh", options, NULL)) >= 0) {
                _cleanup_free_ char *buf = NULL;
                const char *key, *val;

                switch (c) {
                case 'v':
                        arg_verbose = true;
                        break;
                case 'n':
                        arg_dry_run = true;
                        break;
                case 't':
                        if (streq(optarg, "devices"))
                                device_type = TYPE_DEVICES;
                        else if (streq(optarg, "subsystems"))
                                device_type = TYPE_SUBSYSTEMS;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown type --type=%s", optarg);
                        break;
                case 'c':
                        if (streq(optarg, "help")) {
                                dump_device_action_table();
                                return 0;
                        }
                        if (device_action_from_string(optarg) < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown action '%s'", optarg);

                        trigger_handle.action = optarg;
                        break;
                case 's':
                        r = sd_device_enumerator_add_match_subsystem(e, optarg, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add subsystem match '%s': %m", optarg);
                        break;
                case 'S':
                        r = sd_device_enumerator_add_match_subsystem(e, optarg, false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add negative subsystem match '%s': %m", optarg);
                        break;
                case 'a':
                        buf = keyval(optarg, &key, &val);
                        if (!buf)
                                return log_oom();
                        r = sd_device_enumerator_add_match_sysattr(e, key, val, true);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add sysattr match '%s=%s': %m", key, val);
                        break;
                case 'A':
                        buf = keyval(optarg, &key, &val);
                        if (!buf)
                                return log_oom();
                        r = sd_device_enumerator_add_match_sysattr(e, key, val, false);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add negative sysattr match '%s=%s': %m", key, val);
                        break;
                case 'p':
                        buf = keyval(optarg, &key, &val);
                        if (!buf)
                                return log_oom();
                        r = sd_device_enumerator_add_match_property(e, key, val);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add property match '%s=%s': %m", key, val);
                        break;
                case 'g':
                        r = sd_device_enumerator_add_match_tag(e, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add tag match '%s': %m", optarg);
                        break;
                case 'y':
                        r = sd_device_enumerator_add_match_sysname(e, optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add sysname match '%s': %m", optarg);
                        break;
                case 'b': {
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                        r = find_device(optarg, "/sys", &dev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open the device '%s': %m", optarg);

                        r = device_enumerator_add_match_parent_incremental(e, dev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add parent match '%s': %m", optarg);
                        break;
                }
                case 'u':
                        r = sd_id128_from_string(optarg, &id);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse UUID '%s': %m", optarg);
                        break;
                case 'w':
                        settle = true;
                        break;

                case ARG_NAME: {
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                        r = find_device(optarg, "/dev/", &dev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open the device '%s': %m", optarg);

                        r = device_enumerator_add_match_parent_incremental(e, dev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add parent match '%s': %m", optarg);
                        break;
                }

                case ARG_PING: {
                        ping = true;
                        if (optarg) {
                                r = parse_sec(optarg, &ping_timeout_usec);
                                if (r < 0)
                                        log_error_errno(r, "Failed to parse timeout value '%s', ignoring: %m", optarg);
                        }
                        break;
                }

                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached("Unknown option");
                }
        }

        if (ping) {
                _cleanup_(udev_ctrl_unrefp) struct udev_ctrl *uctrl = NULL;

                r = udev_ctrl_new(&uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to initialize udev control: %m");

                r = udev_ctrl_send_ping(uctrl);
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to udev daemon: %m");

                r = udev_ctrl_wait(uctrl, ping_timeout_usec);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for daemon to reply: %m");
        }

        for (; optind < argc; optind++) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                r = find_device(argv[optind], NULL, &dev);
                if (r < 0)
                        return log_error_errno(r, "Failed to open the device '%s': %m", argv[optind]);

                r = device_enumerator_add_match_parent_incremental(e, dev);
                if (r < 0)
                        return log_error_errno(r, "Failed to add parent match '%s': %m", argv[optind]);
        }

        if (sd_id128_is_null(id))
                 assert_se(sd_id128_randomize(&id) >= 0);

        id128_to_uuid_string(id, trigger_handle.synth_uuid);

        if (settle) {
                settle_set = set_new(&string_hash_ops);
                if (!settle_set)
                        return log_oom();

                trigger_handle.settle_set = settle_set;

                r = sd_event_default(&event);
                if (r < 0)
                        return log_error_errno(r, "Failed to get default event: %m");

                r = sd_device_monitor_new(&m);
                if (r < 0)
                        return log_error_errno(r, "Failed to create device monitor object: %m");

                r = sd_device_monitor_attach_event(m, event);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach event to device monitor: %m");

                r = sd_device_monitor_start(m, device_monitor_handler, &trigger_handle);
                if (r < 0)
                        return log_error_errno(r, "Failed to start device monitor: %m");
        }

        switch (device_type) {
        case TYPE_SUBSYSTEMS:
                r = device_enumerator_scan_subsystems(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan subsystems: %m");
                break;
        case TYPE_DEVICES:
                r = device_enumerator_scan_devices(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan devices: %m");
                break;
        default:
                assert_not_reached("Unknown device type");
        }

        r = exec_list(e, &trigger_handle);
        if (r < 0)
                return r;

        if (event && !set_isempty(trigger_handle.settle_set)) {
                r = sd_event_loop(event);
                if (r < 0)
                        return log_error_errno(r, "Event loop failed: %m");
        }

        return 0;
}
