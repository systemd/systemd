/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2010-2017 Canonical
  Copyright © 2018 Dell Inc.
***/

#include <errno.h>
#include <getopt.h>
#include <linux/fiemap.h>
#include <stdio.h>

#include "sd-messages.h"

#include "def.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "sleep-config.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static char *arg_verb = NULL;

static int write_hibernate_location_info(void) {
        _cleanup_free_ char *device = NULL, *type = NULL;
        _cleanup_free_ struct fiemap *fiemap = NULL;
        char offset_str[DECIMAL_STR_MAX(uint64_t)];
        char device_str[DECIMAL_STR_MAX(uint64_t)];
        _cleanup_close_ int fd = -1;
        struct stat stb;
        uint64_t offset;
        int r;

        r = find_hibernate_location(&device, &type, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Unable to find hibernation location: %m");

        /* if it's a swap partition, we just write the disk to /sys/power/resume */
        if (streq(type, "partition")) {
                r = write_string_file("/sys/power/resume", device, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0)
                        return log_debug_errno(r, "Faileed to write partitoin device to /sys/power/resume: %m");

                return r;
        }
        if (!streq(type, "file"))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid hibernate type: %s", type);

        /* Only available in 4.17+ */
        if (access("/sys/power/resume_offset", W_OK) < 0) {
                if (errno == ENOENT) {
                        log_debug("Kernel too old, can't configure resume offset, ignoring.");
                        return 0;
                }

                return log_debug_errno(errno, "/sys/power/resume_offset not writeable: %m");
        }

        fd = open(device, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return log_debug_errno(errno, "Unable to open '%s': %m", device);
        r = fstat(fd, &stb);
        if (r < 0)
                return log_debug_errno(errno, "Unable to stat %s: %m", device);

        r = read_fiemap(fd, &fiemap);
        if (r < 0)
                return log_debug_errno(r, "Unable to read extent map for '%s': %m", device);
        if (fiemap->fm_mapped_extents == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "No extents found in '%s'", device);

        offset = fiemap->fm_extents[0].fe_physical / page_size();
        xsprintf(offset_str, "%" PRIu64, offset);
        r = write_string_file("/sys/power/resume_offset", offset_str, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write offset '%s': %m", offset_str);

        xsprintf(device_str, "%lx", (unsigned long) stb.st_dev);
        r = write_string_file("/sys/power/resume", device_str, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write device '%s': %m", device_str);

        return 0;
}

static int write_mode(char **modes) {
        int r = 0;
        char **mode;

        STRV_FOREACH(mode, modes) {
                int k;

                k = write_string_file("/sys/power/disk", *mode, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (k >= 0)
                        return 0;

                log_debug_errno(k, "Failed to write '%s' to /sys/power/disk: %m", *mode);
                if (r >= 0)
                        r = k;
        }

        return r;
}

static int write_state(FILE **f, char **states) {
        char **state;
        int r = 0;

        STRV_FOREACH(state, states) {
                int k;

                k = write_string_stream(*f, *state, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (k >= 0)
                        return 0;
                log_debug_errno(k, "Failed to write '%s' to /sys/power/state: %m", *state);
                if (r >= 0)
                        r = k;

                fclose(*f);
                *f = fopen("/sys/power/state", "we");
                if (!*f)
                        return -errno;
        }

        return r;
}

static int execute(char **modes, char **states) {
        char *arguments[] = { NULL, (char *) "pre", arg_verb, NULL };
        static const char *const dirs[] = { SYSTEM_SLEEP_PATH, NULL };

        int r;
        _cleanup_fclose_ FILE *f = NULL;

        /* This file is opened first, so that if we hit an error,
         * we can abort before modifying any state. */
        f = fopen("/sys/power/state", "we");
        if (!f)
                return log_error_errno(errno, "Failed to open /sys/power/state: %m");

        setvbuf(f, NULL, _IONBF, 0);

        /* Configure the hibernation mode */
        if (!strv_isempty(modes)) {
                r = write_hibernate_location_info();
                if (r < 0)
                        return log_error_errno(r, "Failed to write hibernation disk offset: %m");
                r = write_mode(modes);
                if (r < 0)
                        return log_error_errno(r, "Failed to write mode to /sys/power/disk: %m");
                ;
        }

        execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, arguments, NULL);

        log_struct(LOG_INFO, "MESSAGE_ID=" SD_MESSAGE_SLEEP_START_STR, LOG_MESSAGE("Suspending system..."), "SLEEP=%s", arg_verb);

        r = write_state(&f, states);
        if (r < 0)
                log_struct_errno(LOG_ERR,
                                 r,
                                 "MESSAGE_ID=" SD_MESSAGE_SLEEP_STOP_STR,
                                 LOG_MESSAGE("Failed to suspend system. System resumed again: %m"),
                                 "SLEEP=%s",
                                 arg_verb);
        else
                log_struct(LOG_INFO, "MESSAGE_ID=" SD_MESSAGE_SLEEP_STOP_STR, LOG_MESSAGE("System resumed."), "SLEEP=%s", arg_verb);

        arguments[1] = (char *) "post";
        execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, arguments, NULL);

        return r;
}

static int rtc_read_time(uint64_t *ret_sec) {
        _cleanup_free_ char *t = NULL;
        int r;

        r = read_one_line_file("/sys/class/rtc/rtc0/since_epoch", &t);
        if (r < 0)
                return log_error_errno(r, "Failed to read RTC time: %m");

        r = safe_atou64(t, ret_sec);
        if (r < 0)
                return log_error_errno(r, "Failed to parse RTC time '%s': %m", t);

        return 0;
}

static int rtc_write_wake_alarm(uint64_t sec) {
        char buf[DECIMAL_STR_MAX(uint64_t)];
        int r;

        xsprintf(buf, "%" PRIu64, sec);

        r = write_string_file("/sys/class/rtc/rtc0/wakealarm", buf, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s' to /sys/class/rtc/rtc0/wakealarm: %m", buf);

        return 0;
}

static int execute_s2h(usec_t hibernate_delay_sec) {

        _cleanup_strv_free_ char **hibernate_modes = NULL, **hibernate_states = NULL, **suspend_modes = NULL, **suspend_states = NULL;
        usec_t original_time, wake_time, cmp_time;
        int r;

        r = parse_sleep_config("suspend", NULL, &suspend_modes, &suspend_states, NULL);
        if (r < 0)
                return r;

        r = parse_sleep_config("hibernate", NULL, &hibernate_modes, &hibernate_states, NULL);
        if (r < 0)
                return r;

        r = rtc_read_time(&original_time);
        if (r < 0)
                return r;

        wake_time = original_time + DIV_ROUND_UP(hibernate_delay_sec, USEC_PER_SEC);
        r = rtc_write_wake_alarm(wake_time);
        if (r < 0)
                return r;

        log_debug("Set RTC wake alarm for %" PRIu64, wake_time);

        r = execute(suspend_modes, suspend_states);
        if (r < 0)
                return r;

        /* Reset RTC right-away */
        r = rtc_write_wake_alarm(0);
        if (r < 0)
                return r;

        r = rtc_read_time(&cmp_time);
        if (r < 0)
                return r;

        log_debug("Woke up at %" PRIu64, cmp_time);

        if (cmp_time < wake_time) /* We woke up before the alarm time, we are done. */
                return 0;

        /* If woken up after alarm time, hibernate */
        r = execute(hibernate_modes, hibernate_states);
        if (r < 0) {
                log_notice("Couldn't hibernate, will try to suspend again.");
                r = execute(suspend_modes, suspend_states);
                if (r < 0) {
                        log_notice("Could neither hibernate nor suspend again, giving up.");
                        return r;
                }
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-suspend.service", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%s COMMAND\n\n"
               "Suspend the system, hibernate the system, or both.\n\n"
               "  -h --help              Show this help and exit\n"
               "  --version              Print version string and exit\n"
               "\nCommands:\n"
               "  suspend                Suspend the system\n"
               "  hibernate              Hibernate the system\n"
               "  hybrid-sleep           Both hibernate and suspend the system\n"
               "  suspend-then-hibernate Initially suspend and then hibernate\n"
               "                         the system after a fixed period of time\n"
               "\nSee the %s for details.\n",
               program_invocation_short_name,
               link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum
        {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = { { "help", no_argument, NULL, 'h' }, { "version", no_argument, NULL, ARG_VERSION }, {} };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc - optind != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Usage: %s COMMAND", program_invocation_short_name);

        arg_verb = argv[optind];

        if (!STR_IN_SET(arg_verb, "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Unknown command '%s'.", arg_verb);

        return 1 /* work to do */;
}

static int run(int argc, char *argv[]) {
        bool allow;
        _cleanup_strv_free_ char **modes = NULL, **states = NULL;
        usec_t delay = 0;
        int r;

        log_setup_service();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        r = parse_sleep_config(arg_verb, &allow, &modes, &states, &delay);
        if (r < 0)
                return r;

        if (!allow)
                return log_error_errno(SYNTHETIC_ERRNO(EACCES), "Sleep mode \"%s\" is disabled by configuration, refusing.", arg_verb);

        if (streq(arg_verb, "suspend-then-hibernate"))
                return execute_s2h(delay);
        else
                return execute(modes, states);
}

DEFINE_MAIN_FUNCTION(run);
