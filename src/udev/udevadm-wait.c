/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "inotify-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "udev-util.h"
#include "udevadm.h"

static char **arg_devices = NULL;
static sd_device **arg_devices_to_be_removed = NULL;
static usec_t arg_timeout_usec = USEC_INFINITY;
static bool arg_initialized = true;
static bool arg_removed = false;
static bool arg_settle = false;

static void devices_freep(sd_device ***devices) {
        if (!*devices)
                return;

        for (sd_device **dev = *devices; dev && *dev; dev++)
                sd_device_unref(*dev);

        free(*devices);
}

STATIC_DESTRUCTOR_REGISTER(arg_devices, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_devices_to_be_removed, devices_freep);

static int find_devices_to_be_removed(void) {
        size_t n = 0;

        if (!arg_removed)
                return 0;

        STRV_FOREACH(p, arg_devices) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                if (sd_device_new_from_syspath_or_devname(&dev, *p) < 0)
                        continue;

                if (!GREEDY_REALLOC(arg_devices_to_be_removed, n + 2))
                        return -ENOMEM;

                arg_devices_to_be_removed[n++] = TAKE_PTR(dev);
                arg_devices_to_be_removed[n] = NULL;
        }

        return 0;
}

static int check_device(const char *path) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(path);

        if (access(path, F_OK) < 0)
                return arg_removed ? true : -errno;

        if (arg_removed)
                return false;

        if (!arg_initialized)
                return true;

        r = sd_device_new_from_syspath_or_devname(&dev, path);
        if (r < 0)
                return r;

        return sd_device_get_is_initialized(dev);
}

static bool check(void) {
        int r;

        if (arg_settle) {
                r = udev_queue_is_empty();
                if (r <= 0) {
                        if (r < 0)
                                log_warning_errno(r, "Failed to check if udev queue is empty, assuming not empty: %m");
                        return false;
                }
        }

        STRV_FOREACH(p, arg_devices) {
                r = check_device(*p);
                if (r < 0) {
                        if (!ERRNO_IS_DEVICE_ABSENT(r))
                                log_warning_errno(r, "Failed to check if device \"%s\" %s, assuming %s.: %m",
                                                  *p,
                                                  arg_initialized ? "is initialized" : "exists",
                                                  arg_initialized ? "not initialized" : "not exist");
                        return false;
                }
        }

        assert(arg_removed || !arg_devices_to_be_removed);
        for (sd_device **dev = arg_devices_to_be_removed; dev && *dev; dev++) {
                const char *syspath;

                assert_se(sd_device_get_syspath(*dev, &syspath) >= 0);

                if (access(syspath, F_OK) >= 0)
                        return false;
        }

        return true;
}

static int on_inotify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        union inotify_event_buffer buffer;
        ssize_t l;

        assert(fd >= 0);

        l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (ERRNO_IS_TRANSIENT(errno))
                        return 0;

                log_warning_errno(errno, "Failed to read inotify event, ignoring: %m");
                return 0;
        }

        if (check())
                return sd_event_exit(sd_event_source_get_event(s), 0);

        return 0;
}

static int inotify_add_device(int fd, const char *path) {
        _cleanup_free_ char *prefix = NULL;
        int r;

        assert(fd >= 0);
        assert(path);

        for (;;) {
                _cleanup_free_ char *p = NULL;

                r = path_extract_directory(prefix ?: path, &p);
                if (r < 0)
                        return r;

                if (inotify_add_watch(fd, p, IN_CREATE | IN_DELETE | IN_MOVED_TO) < 0)
                        return -errno;

                if (path_equal(p, "/dev") || path_equal(p, "/sys"))
                        return 0;

                free_and_replace(prefix, p);
        }
}

static int inotify_add_udev_queue(int fd) {
        assert(fd >= 0);

        if (!arg_settle)
                return 0;

        if (inotify_add_watch(fd, "/run/udev" , IN_CREATE | IN_DELETE) < 0)
                return -errno;

        return 0;
}

static int setup_inotify(sd_event *event, int *ret_fd) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(event);

        fd = inotify_init1(IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = sd_event_add_io(event, &s, fd, EPOLLIN, on_inotify, NULL);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(s, "inotify-event-source");
        if (r < 0)
                return r;

        r = sd_event_source_set_floating(s, true);
        if (r < 0)
                return r;

        if (ret_fd)
                *ret_fd = fd;

        TAKE_FD(fd);
        return 0;
}

static int setup_timer(sd_event *event) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(event);

        if (arg_timeout_usec == USEC_INFINITY)
                return 0;

        r = sd_event_add_time_relative(event, &s, clock_boottime_or_monotonic(),
                                       arg_timeout_usec, 0, NULL, INT_TO_PTR(-ETIMEDOUT));
        if (r < 0)
                return r;

        r = sd_event_source_set_description(s, "timeout-event-source");
        if (r < 0)
                return r;

        return sd_event_source_set_floating(s, true);
}

static int help(void) {
        printf("%s wait [OPTIONS] DEVICE [DEVICE…]\n\n"
               "Wait for devices or device symlinks being created.\n\n"
               "  -h --help             Print this message\n"
               "  -V --version          Print version of the program\n"
               "  -t --timeout=SEC      Maximum time to wait for the device\n"
               "     --initialized=BOOL Wait for devices being initialized by systemd-udevd\n"
               "     --removed          Wait for devices being removed\n"
               "     --settle           Also wait for all queued events being processed\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_INITIALIZED = 0x100,
                ARG_REMOVED,
                ARG_SETTLE,
        };

        static const struct option options[] = {
                { "timeout",     required_argument, NULL, 't'             },
                { "initialized", required_argument, NULL, ARG_INITIALIZED },
                { "removed",     no_argument,       NULL, ARG_REMOVED     },
                { "settle",      no_argument,       NULL, ARG_SETTLE      },
                { "help",        no_argument,       NULL, 'h'             },
                { "version",     no_argument,       NULL, 'V'             },
                {}
        };

        int c, r;

        while ((c = getopt_long(argc, argv, "t:hV", options, NULL)) >= 0)
                switch (c) {
                case 't':
                        r = parse_sec(optarg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse -t/--timeout= parameter: %s", optarg);
                        break;

                case ARG_INITIALIZED:
                        r = parse_boolean(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --initialized= parameter: %s", optarg);
                        arg_initialized = r;
                        break;

                case ARG_REMOVED:
                        arg_removed = true;
                        break;

                case ARG_SETTLE:
                        arg_settle = true;
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

        if (arg_removed)
                arg_initialized = false;

        if (optind >= argc)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Too few arguments, expected at least one device path or device symlink.");

        arg_devices = strv_copy(argv + optind);
        if (!arg_devices)
                return log_oom();

        return 1; /* work to do */
}

int wait_main(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        STRV_FOREACH(p, arg_devices) {
                path_simplify(*p);

                if (!path_is_safe(*p))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Device path cannot contain \"..\".");

                if (!is_device_path(*p))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Specified path \"%s\" does not start with \"/dev\" or \"/sys\".", *p);
        }

        if (check())
                return 0;

        r = sd_event_default(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize sd-event: %m");

        r = setup_timer(event);
        if (r < 0)
                return log_error_errno(r, "Failed to set up timeout: %m");

        r = setup_inotify(event, &fd);
        if (r < 0)
                return log_error_errno(r, "Failed to set up inotify: %m");

        STRV_FOREACH(p, arg_devices) {
                r = inotify_add_device(fd, *p);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch \"%s\": %m", *p);
        }

        r = inotify_add_udev_queue(fd);
        if (r < 0)
                return log_error_errno(r, "Failed to watch udev queue: %m");

        r = find_devices_to_be_removed();
        if (r < 0)
                return log_error_errno(r, "Failed to find devices: %m");

        /* Check again, as devices may be created, initialized, or removed during we set up inotify events. */
        if (check())
                return 0;

        r = sd_event_loop(event);
        if (r == -ETIMEDOUT)
                return log_error_errno(r, "Timed out for waiting devices being %s.",
                                       arg_removed ? "removed" :
                                       arg_initialized ? "initialized" : "created");
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}
