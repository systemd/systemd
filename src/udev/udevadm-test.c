/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright © 2003-2004 Greg Kroah-Hartman <greg@kroah.com>
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "sd-device.h"

#include "ansi-color.h"
#include "device-private.h"
#include "device-util.h"
#include "format-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "strxcpyx.h"
#include "terminal-util.h"
#include "udev-builtin.h"
#include "udev-event.h"
#include "udev-format.h"
#include "udevadm-util.h"
#include "udevadm.h"
#include "user-util.h"

static sd_device_action_t arg_action = SD_DEVICE_ADD;
static ResolveNameTiming arg_resolve_name_timing = RESOLVE_NAME_EARLY;
static const char *arg_syspath = NULL;

static int help(void) {

        printf("%s test [OPTIONS] DEVPATH\n\n"
               "Test an event run.\n\n"
               "  -h --help                            Show this help\n"
               "  -V --version                         Show package version\n"
               "  -a --action=ACTION|help              Set action string\n"
               "  -N --resolve-names=early|late|never  When to resolve names\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "action",        required_argument, NULL, 'a' },
                { "resolve-names", required_argument, NULL, 'N' },
                { "version",       no_argument,       NULL, 'V' },
                { "help",          no_argument,       NULL, 'h' },
                {}
        };

        int r, c;

        while ((c = getopt_long(argc, argv, "a:N:Vh", options, NULL)) >= 0)
                switch (c) {
                case 'a':
                        r = parse_device_action(optarg, &arg_action);
                        if (r < 0)
                                return log_error_errno(r, "Invalid action '%s'", optarg);
                        if (r == 0)
                                return 0;
                        break;
                case 'N':
                        arg_resolve_name_timing = resolve_name_timing_from_string(optarg);
                        if (arg_resolve_name_timing < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "--resolve-names= must be early, late or never");
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

        arg_syspath = argv[optind];
        if (!arg_syspath)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "syspath parameter missing.");

        return 1;
}

int test_main(int argc, char *argv[], void *userdata) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        _cleanup_(udev_event_freep) UdevEvent *event = NULL;
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        sigset_t mask, sigmask_orig;
        int r;

        log_set_max_level(LOG_DEBUG);
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        printf("This program is for debugging only, it does not run any program\n"
               "specified by a RUN key. It may show incorrect results, because\n"
               "some values may be different, or not available at a simulation run.\n"
               "\n");

        assert_se(sigprocmask(SIG_SETMASK, NULL, &sigmask_orig) >= 0);

        udev_builtin_init();

        r = udev_rules_load(&rules, arg_resolve_name_timing);
        if (r < 0) {
                log_error_errno(r, "Failed to read udev rules: %m");
                goto out;
        }

        r = find_device_with_action(arg_syspath, arg_action, &dev);
        if (r < 0) {
                log_error_errno(r, "Failed to open device '%s': %m", arg_syspath);
                goto out;
        }

        /* don't read info from the db */
        device_seal(dev);

        event = udev_event_new(dev, NULL, EVENT_UDEVADM_TEST);

        assert_se(sigfillset(&mask) >= 0);
        assert_se(sigprocmask(SIG_SETMASK, &mask, &sigmask_orig) >= 0);

        udev_event_execute_rules(event, rules);

        printf("%sProperties:%s\n", ansi_highlight(), ansi_normal());
        FOREACH_DEVICE_PROPERTY(dev, key, value)
                printf("  %s=%s\n", key, value);

        if (sd_device_get_tag_first(dev)) {
                printf("%sTags:%s\n", ansi_highlight(), ansi_normal());
                FOREACH_DEVICE_TAG(dev, tag)
                        printf("  %s\n", tag);
        }

        if (sd_device_get_devnum(dev, NULL) >= 0) {

                if (sd_device_get_devlink_first(dev)) {
                        int prio;
                        device_get_devlink_priority(dev, &prio);
                        printf("%sDevice node symlinks:%s (priority=%i)\n", ansi_highlight(), ansi_normal(), prio);
                        FOREACH_DEVICE_DEVLINK(dev, devlink)
                                printf("  %s\n", devlink);
                }

                printf("%sInotify watch:%s\n  %s\n", ansi_highlight(), ansi_normal(), enabled_disabled(event->inotify_watch));

                uid_t uid = event->uid;
                if (!uid_is_valid(uid))
                        (void) device_get_devnode_uid(dev, &uid);
                if (uid_is_valid(uid)) {
                        _cleanup_free_ char *user = uid_to_name(uid);
                        printf("%sDevice node owner:%s\n  %s (uid="UID_FMT")\n", ansi_highlight(), ansi_normal(), strna(user), uid);
                }

                gid_t gid = event->gid;
                if (!gid_is_valid(uid))
                        (void) device_get_devnode_gid(dev, &gid);
                if (gid_is_valid(gid)) {
                        _cleanup_free_ char *group = gid_to_name(gid);
                        printf("%sDevice node group:%s\n  %s (gid="GID_FMT")\n", ansi_highlight(), ansi_normal(), strna(group), gid);
                }

                mode_t mode = event->mode;
                if (mode == MODE_INVALID)
                        (void) device_get_devnode_mode(dev, &mode);
                if (mode != MODE_INVALID)
                        printf("%sDevice node permission:%s\n  %04o\n", ansi_highlight(), ansi_normal(), mode);

                if (!ordered_hashmap_isempty(event->seclabel_list)) {
                        const char *name, *label;
                        printf("%sDevice node security label:%s\n", ansi_highlight(), ansi_normal());
                        ORDERED_HASHMAP_FOREACH_KEY(label, name, event->seclabel_list)
                                printf("  %s : %s\n", name, label);
                }
        }

        if (sd_device_get_ifindex(dev, NULL) >= 0) {
                if (!isempty(event->name))
                        printf("%sNetwork interface name:%s\n  %s\n", ansi_highlight(), ansi_normal(), event->name);

                if (!strv_isempty(event->altnames)) {
                        bool space = true;
                        printf("%sAlternative interface names:%s", ansi_highlight(), ansi_normal());
                        fputstrv(stdout, event->altnames, "\n  ", &space);
                        puts("");
                }
        }

        if (!ordered_hashmap_isempty(event->run_list)) {
                void *val;
                const char *command;
                printf("%sQueued commands:%s\n", ansi_highlight(), ansi_normal());
                ORDERED_HASHMAP_FOREACH_KEY(val, command, event->run_list) {
                        UdevBuiltinCommand builtin_cmd = PTR_TO_UDEV_BUILTIN_CMD(val);

                        if (builtin_cmd != _UDEV_BUILTIN_INVALID)
                                printf("  RUN{builtin} : %s\n", command);
                        else
                                printf("  RUN{program} : %s\n", command);
                }
        }

        r = 0;
out:
        udev_builtin_exit();
        return r;
}
