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
#include "parse-util.h"
#include "sleep-config.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static char* arg_verb = NULL;

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
                r = write_string_file("/sys/power/resume", device, 0);
                if (r < 0)
                        return log_debug_errno(r, "Faileed to write partitoin device to /sys/power/resume: %m");

                return r;
        }
        if (!streq(type, "file")) {
                log_debug("Invalid hibernate type: %s", type);
                return -EINVAL;
        }

        /* Only available in 4.17+ */
        if (access("/sys/power/resume_offset", F_OK) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_debug_errno(errno, "/sys/power/resume_offset unavailable: %m");
        }

        if (access("/sys/power/resume_offset", W_OK) < 0)
                return log_debug_errno(errno, "/sys/power/resume_offset not writeable: %m");

        fd = open(device, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return log_debug_errno(errno, "Unable to open '%s': %m", device);
        r = fstat(fd, &stb);
        if (r < 0)
                return log_debug_errno(errno, "Unable to stat %s: %m", device);

        r = read_fiemap(fd, &fiemap);
        if (r < 0)
                return log_debug_errno(r, "Unable to read extent map for '%s': %m", device);
        if (fiemap->fm_mapped_extents == 0) {
                log_debug("No extents found in '%s'", device);
                return -EINVAL;
        }

        offset = fiemap->fm_extents[0].fe_physical / page_size();
        xsprintf(offset_str, "%" PRIu64, offset);
        r = write_string_file("/sys/power/resume_offset", offset_str, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to write offset '%s': %m", offset_str);

        xsprintf(device_str, "%lx", (unsigned long)stb.st_dev);
        r = write_string_file("/sys/power/resume", device_str, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to write device '%s': %m", device_str);

        return 0;
}

static int write_mode(char **modes) {
        int r = 0;
        char **mode;

        STRV_FOREACH(mode, modes) {
                int k;

                k = write_string_file("/sys/power/disk", *mode, 0);
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

                k = write_string_stream(*f, *state, 0);
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

        char *arguments[] = {
                NULL,
                (char*) "pre",
                arg_verb,
                NULL
        };
        static const char* const dirs[] = {
                SYSTEM_SLEEP_PATH,
                NULL
        };

        int r;
        _cleanup_fclose_ FILE *f = NULL;

        /* This file is opened first, so that if we hit an error,
         * we can abort before modifying any state. */
        f = fopen("/sys/power/state", "we");
        if (!f)
                return log_error_errno(errno, "Failed to open /sys/power/state: %m");

        /* Configure the hibernation mode */
        if (!strv_isempty(modes)) {
                r = write_hibernate_location_info();
                if (r < 0)
                        return log_error_errno(r, "Failed to write hibernation disk offset: %m");
                r = write_mode(modes);
                if (r < 0)
                        return log_error_errno(r, "Failed to write mode to /sys/power/disk: %m");;
        }

        execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, arguments);

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_SLEEP_START_STR,
                   LOG_MESSAGE("Suspending system..."),
                   "SLEEP=%s", arg_verb);

        r = write_state(&f, states);
        if (r < 0)
                return log_error_errno(r, "Failed to write /sys/power/state: %m");

        log_struct(LOG_INFO,
                   "MESSAGE_ID=" SD_MESSAGE_SLEEP_STOP_STR,
                   LOG_MESSAGE("System resumed."),
                   "SLEEP=%s", arg_verb);

        arguments[1] = (char*) "post";
        execute_directories(dirs, DEFAULT_TIMEOUT_USEC, NULL, NULL, arguments);

        return r;
}

static int read_wakealarm(uint64_t *result) {
        _cleanup_free_ char *t = NULL;

        if (read_one_line_file("/sys/class/rtc/rtc0/since_epoch", &t) >= 0)
                return safe_atou64(t, result);
        return -EBADF;
}

static int write_wakealarm(const char *str) {

        _cleanup_fclose_ FILE *f = NULL;
        int r;

        f = fopen("/sys/class/rtc/rtc0/wakealarm", "we");
        if (!f)
                return log_error_errno(errno, "Failed to open /sys/class/rtc/rtc0/wakealarm: %m");

        r = write_string_stream(f, str, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s' to /sys/class/rtc/rtc0/wakealarm: %m", str);

        return 0;
}

static int execute_s2h(usec_t hibernate_delay_sec) {

        _cleanup_strv_free_ char **hibernate_modes = NULL, **hibernate_states = NULL,
                                 **suspend_modes = NULL, **suspend_states = NULL;
        usec_t orig_time, cmp_time;
        char time_str[DECIMAL_STR_MAX(uint64_t)];
        int r;

        r = parse_sleep_config("suspend", &suspend_modes, &suspend_states,
                               NULL);
        if (r < 0)
                return r;

        r = parse_sleep_config("hibernate", &hibernate_modes,
                               &hibernate_states, NULL);
        if (r < 0)
                return r;

        r = read_wakealarm(&orig_time);
        if (r < 0)
                return log_error_errno(errno, "Failed to read time: %d", r);

        orig_time += hibernate_delay_sec / USEC_PER_SEC;
        xsprintf(time_str, "%" PRIu64, orig_time);

        r = write_wakealarm(time_str);
        if (r < 0)
                return r;

        log_debug("Set RTC wake alarm for %s", time_str);

        r = execute(suspend_modes, suspend_states);
        if (r < 0)
                return r;

        r = read_wakealarm(&cmp_time);
        if (r < 0)
                return log_error_errno(errno, "Failed to read time: %d", r);

        /* reset RTC */
        r = write_wakealarm("0");
        if (r < 0)
                return r;

        log_debug("Woke up at %"PRIu64, cmp_time);

        /* if woken up after alarm time, hibernate */
        if (cmp_time >= orig_time)
                r = execute(hibernate_modes, hibernate_states);

        return r;
}

static void help(void) {
        printf("%s COMMAND\n\n"
               "Suspend the system, hibernate the system, or both.\n\n"
               "Commands:\n"
               "  -h --help            Show this help and exit\n"
               "  --version            Print version string and exit\n"
               "  suspend              Suspend the system\n"
               "  hibernate            Hibernate the system\n"
               "  hybrid-sleep         Both hibernate and suspend the system\n"
               "  suspend-then-hibernate Initially suspend and then hibernate\n"
               "                       the system after a fixed period of time\n"
               , program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'           },
                { "version",      no_argument,       NULL, ARG_VERSION   },
                {}
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        return 0; /* done */

                case ARG_VERSION:
                        return version();

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        if (argc - optind != 1) {
                log_error("Usage: %s COMMAND",
                          program_invocation_short_name);
                return -EINVAL;
        }

        arg_verb = argv[optind];

        if (!STR_IN_SET(arg_verb, "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate")) {
                log_error("Unknown command '%s'.", arg_verb);
                return -EINVAL;
        }

        return 1 /* work to do */;
}

int main(int argc, char *argv[]) {
        _cleanup_strv_free_ char **modes = NULL, **states = NULL;
        usec_t delay = 0;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = parse_sleep_config(arg_verb, &modes, &states, &delay);
        if (r < 0)
                goto finish;

        if (streq(arg_verb, "suspend-then-hibernate"))
                r = execute_s2h(delay);
        else
                r = execute(modes, states);

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
