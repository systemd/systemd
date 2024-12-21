/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>
#include <getopt.h>

#include "sd-device.h"
#include "sd-event.h"

#include "device-enumerator-private.h"
#include "device-private.h"
#include "device-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "id128-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "set.h"
#include "static-destruct.h"
#include "string-util.h"
#include "strv.h"
#include "udevadm.h"
#include "udevadm-util.h"
#include "virt.h"

static bool arg_verbose = false;
static bool arg_dry_run = false;
static bool arg_quiet = false;
static bool arg_uuid = false;
static bool arg_settle = false;

static int exec_list(
                sd_device_enumerator *e,
                sd_device_action_t action,
                Set **ret_settle_path_or_ids) {

        _cleanup_set_free_ Set *settle_path_or_ids = NULL;
        int uuid_supported = -1;
        const char *action_str;
        sd_device *d;
        int r, ret = 0;

        assert(e);

        action_str = device_action_to_string(action);

        FOREACH_DEVICE_AND_SUBSYSTEM(e, d) {
                sd_id128_t id = SD_ID128_NULL;
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

                /* Use the UUID mode if the user explicitly asked for it, or if --settle has been specified,
                 * so that we can recognize our own uevent. */
                r = sd_device_trigger_with_uuid(d, action, (arg_uuid || arg_settle) && uuid_supported != 0 ? &id : NULL);
                if (r == -EINVAL && !arg_uuid && arg_settle && uuid_supported < 0) {
                        /* If we specified a UUID because of the settling logic, and we got EINVAL this might
                         * be caused by an old kernel which doesn't know the UUID logic (pre-4.13). Let's try
                         * if it works without the UUID logic then. */
                        r = sd_device_trigger(d, action);
                        if (r != -EINVAL)
                                uuid_supported = false; /* dropping the uuid stuff changed the return code,
                                                         * hence don't bother next time */
                }
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
                        if (ret == 0 && !ignore)
                                ret = r;
                        continue;
                } else
                        log_device_debug(d, "Triggered device with action '%s'.", action_str);

                if (uuid_supported < 0)
                        uuid_supported = true;

                /* If the user asked for it, write event UUID to stdout */
                if (arg_uuid)
                        printf(SD_ID128_UUID_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(id));

                if (arg_settle) {
                        if (uuid_supported) {
                                sd_id128_t *dup;

                                dup = newdup(sd_id128_t, &id, 1);
                                if (!dup)
                                        return log_oom();

                                r = set_ensure_consume(&settle_path_or_ids, &id128_hash_ops_free, dup);
                        } else {
                                char *dup;

                                dup = strdup(syspath);
                                if (!dup)
                                        return log_oom();

                                r = set_ensure_consume(&settle_path_or_ids, &path_hash_ops_free, dup);
                        }
                        if (r < 0)
                                return log_oom();
                }
        }

        if (ret_settle_path_or_ids)
                *ret_settle_path_or_ids = TAKE_PTR(settle_path_or_ids);

        return ret;
}

static int device_monitor_handler(sd_device_monitor *m, sd_device *dev, void *userdata) {
        Set *settle_path_or_ids = * (Set**) ASSERT_PTR(userdata);
        const char *syspath;
        sd_id128_t id;
        int r;

        assert(dev);

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0) {
                log_device_debug_errno(dev, r, "Failed to get syspath of device event, ignoring: %m");
                return 0;
        }

        if (sd_device_get_trigger_uuid(dev, &id) >= 0) {
                _cleanup_free_ sd_id128_t *saved = NULL;

                saved = set_remove(settle_path_or_ids, &id);
                if (!saved) {
                        log_device_debug(dev, "Got uevent not matching expected UUID, ignoring.");
                        return 0;
                }
        } else {
                _cleanup_free_ char *saved = NULL;

                saved = set_remove(settle_path_or_ids, syspath);
                if (!saved) {
                        const char *old_sysname;

                        /* When the device is renamed, the new name is broadcast, and the old name is saved
                         * in INTERFACE_OLD.
                         *
                         * TODO: remove support for INTERFACE_OLD when kernel baseline is bumped to 4.13 or
                         * higher. See 1193448cb68e5a90cab027e16a093bbd367e9494.
                         */

                        if (sd_device_get_property_value(dev, "INTERFACE_OLD", &old_sysname) >= 0) {
                                _cleanup_free_ char *dir = NULL, *old_syspath = NULL;

                                r = path_extract_directory(syspath, &dir);
                                if (r < 0) {
                                        log_device_debug_errno(dev, r,
                                                               "Failed to extract directory from '%s', ignoring: %m",
                                                               syspath);
                                        return 0;
                                }

                                old_syspath = path_join(dir, old_sysname);
                                if (!old_syspath) {
                                        log_oom_debug();
                                        return 0;
                                }

                                saved = set_remove(settle_path_or_ids, old_syspath);
                        }
                }
                if (!saved) {
                        log_device_debug(dev, "Got uevent for unexpected device, ignoring.");
                        return 0;
                }
        }

        if (arg_verbose)
                printf("settle %s\n", syspath);

        if (arg_uuid)
                printf("settle " SD_ID128_UUID_FORMAT_STR "\n", SD_ID128_FORMAT_VAL(id));

        if (set_isempty(settle_path_or_ids))
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
               "  -q --quiet                        Suppress error logging in triggering events\n"
               "  -t --type=                        Type of events to trigger\n"
               "          devices                     sysfs devices (default)\n"
               "          subsystems                  sysfs subsystems and drivers\n"
               "          all                         sysfs devices, subsystems, and drivers\n"
               "  -c --action=ACTION|help           Event action value, default is \"change\"\n"
               "  -s --subsystem-match=SUBSYSTEM    Trigger devices from a matching subsystem\n"
               "  -S --subsystem-nomatch=SUBSYSTEM  Exclude devices from a matching subsystem\n"
               "  -a --attr-match=FILE[=VALUE]      Trigger devices with a matching attribute\n"
               "  -A --attr-nomatch=FILE[=VALUE]    Exclude devices with a matching attribute\n"
               "  -p --property-match=KEY=VALUE     Trigger devices with a matching property\n"
               "  -g --tag-match=TAG                Trigger devices with a matching tag\n"
               "  -y --sysname-match=NAME           Trigger devices with this /sys path\n"
               "     --name-match=NAME              Trigger devices with this /dev name\n"
               "  -b --parent-match=NAME            Trigger devices with that parent device\n"
               "     --include-parents              Trigger parent devices of found devices\n"
               "     --initialized-match            Trigger devices that are already initialized\n"
               "     --initialized-nomatch          Trigger devices that are not initialized yet\n"
               "  -w --settle                       Wait for the triggered events to complete\n"
               "     --wait-daemon[=SECONDS]        Wait for udevd daemon to be initialized\n"
               "                                    before triggering uevents\n"
               "     --uuid                         Print synthetic uevent UUID\n"
               "     --prioritized-subsystem=SUBSYSTEM[,SUBSYSTEM…]\n"
               "                                    Trigger devices from a matching subsystem first\n",
               program_invocation_short_name);

        return 0;
}

int trigger_main(int argc, char *argv[], void *userdata) {
        enum {
                ARG_NAME = 0x100,
                ARG_PING,
                ARG_UUID,
                ARG_PRIORITIZED_SUBSYSTEM,
                ARG_INITIALIZED_MATCH,
                ARG_INITIALIZED_NOMATCH,
                ARG_INCLUDE_PARENTS,
        };

        static const struct option options[] = {
                { "verbose",               no_argument,       NULL, 'v'                       },
                { "dry-run",               no_argument,       NULL, 'n'                       },
                { "quiet",                 no_argument,       NULL, 'q'                       },
                { "type",                  required_argument, NULL, 't'                       },
                { "action",                required_argument, NULL, 'c'                       },
                { "subsystem-match",       required_argument, NULL, 's'                       },
                { "subsystem-nomatch",     required_argument, NULL, 'S'                       },
                { "attr-match",            required_argument, NULL, 'a'                       },
                { "attr-nomatch",          required_argument, NULL, 'A'                       },
                { "property-match",        required_argument, NULL, 'p'                       },
                { "tag-match",             required_argument, NULL, 'g'                       },
                { "sysname-match",         required_argument, NULL, 'y'                       },
                { "name-match",            required_argument, NULL, ARG_NAME                  },
                { "parent-match",          required_argument, NULL, 'b'                       },
                { "include-parents",       no_argument,       NULL, ARG_INCLUDE_PARENTS       },
                { "initialized-match",     no_argument,       NULL, ARG_INITIALIZED_MATCH     },
                { "initialized-nomatch",   no_argument,       NULL, ARG_INITIALIZED_NOMATCH   },
                { "settle",                no_argument,       NULL, 'w'                       },
                { "wait-daemon",           optional_argument, NULL, ARG_PING                  },
                { "version",               no_argument,       NULL, 'V'                       },
                { "help",                  no_argument,       NULL, 'h'                       },
                { "uuid",                  no_argument,       NULL, ARG_UUID                  },
                { "prioritized-subsystem", required_argument, NULL, ARG_PRIORITIZED_SUBSYSTEM },
                {}
        };
        enum {
                TYPE_DEVICES,
                TYPE_SUBSYSTEMS,
                TYPE_ALL,
        } device_type = TYPE_DEVICES;
        sd_device_action_t action = SD_DEVICE_CHANGE;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *m = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_set_free_ Set *settle_path_or_ids = NULL;
        usec_t ping_timeout_usec = 5 * USEC_PER_SEC;
        bool ping = false;
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

        while ((c = getopt_long(argc, argv, "vnqt:c:s:S:a:A:p:g:y:b:wVh", options, NULL)) >= 0) {
                _cleanup_free_ char *buf = NULL;
                const char *key, *val;

                switch (c) {
                case 'v':
                        arg_verbose = true;
                        break;
                case 'n':
                        arg_dry_run = true;
                        break;
                case 'q':
                        arg_quiet = true;
                        break;
                case 't':
                        if (streq(optarg, "devices"))
                                device_type = TYPE_DEVICES;
                        else if (streq(optarg, "subsystems"))
                                device_type = TYPE_SUBSYSTEMS;
                        else if (streq(optarg, "all"))
                                device_type = TYPE_ALL;
                        else
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown type --type=%s", optarg);
                        break;
                case 'c':
                        r = parse_device_action(optarg, &action);
                        if (r < 0)
                                return log_error_errno(r, "Unknown action '%s'", optarg);
                        if (r == 0)
                                return 0;
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
                case ARG_INCLUDE_PARENTS:
                        r = sd_device_enumerator_add_all_parents(e);
                        if (r < 0)
                                return log_error_errno(r, "Failed to always include all parents: %m");
                        break;
                case 'w':
                        arg_settle = true;
                        break;

                case ARG_NAME: {
                        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                        r = find_device(optarg, "/dev", &dev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to open the device '%s': %m", optarg);

                        r = device_enumerator_add_match_parent_incremental(e, dev);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add parent match '%s': %m", optarg);
                        break;
                }

                case ARG_PING:
                        ping = true;
                        if (optarg) {
                                r = parse_sec(optarg, &ping_timeout_usec);
                                if (r < 0)
                                        log_error_errno(r, "Failed to parse timeout value '%s', ignoring: %m", optarg);
                        }
                        break;

                case ARG_UUID:
                        arg_uuid = true;
                        break;

                case ARG_PRIORITIZED_SUBSYSTEM: {
                        _cleanup_strv_free_ char **subsystems = NULL;

                        subsystems = strv_split(optarg, ",");
                        if (!subsystems)
                                return log_error_errno(r, "Failed to parse prioritized subsystem '%s': %m", optarg);

                        STRV_FOREACH(p, subsystems) {
                                r = device_enumerator_add_prioritized_subsystem(e, *p);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to add prioritized subsystem '%s': %m", *p);
                        }
                        break;
                }
                case ARG_INITIALIZED_MATCH:
                case ARG_INITIALIZED_NOMATCH:
                        r = device_enumerator_add_match_is_initialized(e, c == ARG_INITIALIZED_MATCH ? MATCH_INITIALIZED_YES : MATCH_INITIALIZED_NO);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set initialized filter: %m");
                        break;
                case 'V':
                        return print_version();
                case 'h':
                        return help();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }
        }

        if (ping) {
                r = udev_ping(ping_timeout_usec, /* ignore_connection_failure = */ false);
                if (r < 0)
                        return r;
                assert(r > 0);
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

                r = sd_device_monitor_start(m, device_monitor_handler, &settle_path_or_ids);
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
        case TYPE_ALL:
                r = device_enumerator_scan_devices_and_subsystems(e);
                if (r < 0)
                        return log_error_errno(r, "Failed to scan devices and subsystems: %m");
                break;
        default:
                assert_not_reached();
        }

        r = exec_list(e, action, arg_settle ? &settle_path_or_ids : NULL);
        if (r < 0)
                return r;

        if (!set_isempty(settle_path_or_ids)) {
                r = sd_event_loop(event);
                if (r < 0)
                        return log_error_errno(r, "Event loop failed: %m");
        }

        return 0;
}
