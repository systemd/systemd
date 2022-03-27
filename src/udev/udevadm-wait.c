/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-event.h"

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "errno-util.h"
#include "fd-util.h"
#include "inotify-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "strv.h"
#include "udev-util.h"
#include "udevadm.h"

static usec_t arg_timeout_usec = USEC_INFINITY;
static bool arg_initialized = true;
static bool arg_removed = false;
static bool arg_settle = false;

typedef struct Context {
        sd_event *event;
        int inotify_fd;
        char **devices;
        sd_device **devices_to_be_removed;
        size_t n_devices_to_be_removed;
} Context;

static void context_clear(Context *c) {
        if (!c)
                return;

        strv_free(c->devices);

        for (size_t i = 0; i < c->n_devices_to_be_removed; i++)
                sd_device_unref(c->devices_to_be_removed[i]);

        free(c->devices_to_be_removed);

        sd_event_unref(c->event);
        safe_close(c->inotify_fd);
}

static int context_find_devices_to_be_removed(Context *c) {
        assert(c);

        if (!arg_removed)
                return 0;

        STRV_FOREACH(p, c->devices) {
                _cleanup_(sd_device_unrefp) sd_device *dev = NULL;

                if (sd_device_new_from_syspath_or_devname(&dev, *p) < 0)
                        continue;

                if (!GREEDY_REALLOC(c->devices_to_be_removed, c->n_devices_to_be_removed + 1))
                        return -ENOMEM;

                c->devices_to_be_removed[c->n_devices_to_be_removed++] = TAKE_PTR(dev);
        }

        return 0;
}

static int context_inotify_add_device(Context *c, const char *path, bool only_syspath) {
        _cleanup_free_ char *resolved = NULL, *prefix = NULL;
        int r;

        assert(c);
        assert(c->inotify_fd >= 0);
        assert(path);

        if (path_startswith(path, "/dev")) {
                _cleanup_free_ char *p = NULL;

                if (only_syspath)
                        return 0;

                r = path_extract_directory(path, &p);
                if (r < 0)
                        return r;

                if (inotify_add_watch(c->inotify_fd, p, IN_CREATE | IN_DELETE | IN_MOVED_TO) < 0)
                        return -errno;

                return 0;
        }

        r = chase_symlinks(path, "/sys", CHASE_NONEXISTENT, &resolved, NULL);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *p = NULL;

                r = path_extract_directory(prefix ?: resolved, &p);
                if (r < 0)
                        return r;

                if (inotify_add_watch(c->inotify_fd, p, IN_CREATE | IN_DELETE | IN_MOVED_TO) < 0)
                        return -errno;

                if (path_equal(p, "/sys"))
                        return 0;

                free_and_replace(prefix, p);
        }
}

static int context_inotify_add_udev_queue(Context *c) {
        assert(c);
        assert(c->inotify_fd >= 0);

        if (!arg_settle)
                return 0;

        if (inotify_add_watch(c->inotify_fd, "/run/udev" , IN_CREATE | IN_DELETE) < 0)
                return -errno;

        return 0;
}

static int context_check_device(const char *path) {
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

static bool context_check(Context *c) {
        int r;

        assert(c);

        if (arg_settle) {
                r = udev_queue_is_empty();
                if (r <= 0) {
                        if (r < 0)
                                log_warning_errno(r, "Failed to check if udev queue is empty, assuming not empty: %m");
                        return false;
                }
        }

        STRV_FOREACH(p, c->devices) {
                r = context_check_device(*p);
                if (r < 0) {
                        if (!ERRNO_IS_DEVICE_ABSENT(r))
                                log_warning_errno(r, "Failed to check if device \"%s\" %s, assuming %s.: %m",
                                                  *p,
                                                  arg_initialized ? "is initialized" : "exists",
                                                  arg_initialized ? "not initialized" : "not exist");
                        return false;
                }
        }

        assert(arg_removed || c->n_devices_to_be_removed == 0);
        for (size_t i = 0; i < c->n_devices_to_be_removed; i++) {
                const char *syspath;

                assert_se(sd_device_get_syspath(c->devices_to_be_removed[i], &syspath) >= 0);

                if (access(syspath, F_OK) >= 0)
                        return false;
        }

        STRV_FOREACH(p, c->devices) {
                r = context_inotify_add_device(c, *p, /* only_syspath = */ true);
                if (r < 0)
                        log_warning_errno(r, "Failed to readd inotify watch for \"%s\", ignoring: %m", *p);
        }

        return true;
}

static int on_inotify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Context *c = ASSERT_PTR(userdata);
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

        if (context_check(c))
                return sd_event_exit(sd_event_source_get_event(s), 0);

        return 0;
}

static int context_setup_inotify(Context *c) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(c);
        assert(c->event);

        fd = inotify_init1(IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = sd_event_add_io(c->event, &s, fd, EPOLLIN, on_inotify, c);
        if (r < 0)
                return r;

        r = sd_event_source_set_description(s, "inotify-event-source");
        if (r < 0)
                return r;

        r = sd_event_source_set_floating(s, true);
        if (r < 0)
                return r;

        c->inotify_fd = TAKE_FD(fd);
        return 0;
}

static int context_setup_timer(Context *c) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *s = NULL;
        int r;

        assert(c);
        assert(c->event);

        if (arg_timeout_usec == USEC_INFINITY)
                return 0;

        r = sd_event_add_time_relative(c->event, &s, clock_boottime_or_monotonic(),
                                       arg_timeout_usec, 0, NULL, INT_TO_PTR(-ETIMEDOUT));
        if (r < 0)
                return r;

        r = sd_event_source_set_description(s, "timeout-event-source");
        if (r < 0)
                return r;

        return sd_event_source_set_floating(s, true);
}

static int context_setup(Context *c) {
        int r;

        assert(c);

        STRV_FOREACH(p, c->devices) {
                path_simplify(*p);

                if (!path_is_safe(*p))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Device path cannot contain \"..\".");

                if (!is_device_path(*p))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Specified path \"%s\" does not start with \"/dev\" or \"/sys\".", *p);
        }

        r = sd_event_default(&c->event);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize sd-event: %m");

        r = context_setup_timer(c);
        if (r < 0)
                return log_error_errno(r, "Failed to set up timeout: %m");

        r = context_setup_inotify(c);
        if (r < 0)
                return log_error_errno(r, "Failed to set up inotify: %m");

        STRV_FOREACH(p, c->devices) {
                r = context_inotify_add_device(c, *p, /* only_syspath = */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to watch \"%s\": %m", *p);
        }

        r = context_inotify_add_udev_queue(c);
        if (r < 0)
                return log_error_errno(r, "Failed to watch udev queue: %m");

        r = context_find_devices_to_be_removed(c);
        if (r < 0)
                return log_error_errno(r, "Failed to find devices: %m");

        return 0;
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

static int parse_argv(int argc, char *argv[], Context *context) {
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

        assert(context);

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

        context->devices = strv_copy(argv + optind);
        if (!context->devices)
                return log_oom();

        return 1; /* work to do */
}

int wait_main(int argc, char *argv[], void *userdata) {
        _cleanup_(context_clear) Context c = { .inotify_fd = -1, };
        int r;

        r = parse_argv(argc, argv, &c);
        if (r <= 0)
                return r;

        r = context_setup(&c);
        if (r < 0)
                return r;

        /* Check before entering the event loop, as devices may be already created, initialized, or removed. */
        if (context_check(&c))
                return 0;

        r = sd_event_loop(c.event);
        if (r == -ETIMEDOUT)
                return log_error_errno(r, "Timed out for waiting devices being %s.",
                                       arg_removed ? "removed" :
                                       arg_initialized ? "initialized" : "created");
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}
