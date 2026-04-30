/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blockdev-util.h"
#include "device-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "format-table.h"
#include "glyph-util.h"
#include "hash-funcs.h"
#include "help-util.h"
#include "lock-util.h"
#include "options.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "signal-util.h"
#include "sort-util.h"
#include "static-destruct.h"
#include "strv.h"
#include "time-util.h"
#include "udevadm.h"

static usec_t arg_timeout_usec = USEC_INFINITY;
static char **arg_devices = NULL;
static char **arg_backing = NULL;
static char **arg_cmdline = NULL;
static bool arg_print = false;

STATIC_DESTRUCTOR_REGISTER(arg_devices, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_backing, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_cmdline, strv_freep);

static int help(void) {
        _cleanup_(table_unrefp) Table *options = NULL;
        int r;

        r = option_parser_get_help_table_ns("udevadm-lock", &options);
        if (r < 0)
                return r;

        help_cmdline("lock [OPTIONS...] COMMAND");
        help_cmdline("lock [OPTIONS...] --print");
        help_abstract("Lock a block device and run a command.");
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

        OptionParser opts = { argc, argv, OPTION_PARSER_STOP_AT_FIRST_NONOPTION, "udevadm-lock" };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_NAMESPACE("udevadm-lock"): {}

                OPTION_COMMON_HELP:
                        return help();

                OPTION('V', "version", NULL, "Show package version"):
                        return print_version();

                OPTION('d', "device", "DEVICE", "Block device to lock"): {} /* fall through */
                OPTION('b', "backing", "FILE", "File whose backing block device to lock"): {
                        _cleanup_free_ char *s = NULL;
                        char ***l = opts.opt->short_code == 'd' ? &arg_devices : &arg_backing;

                        r = path_make_absolute_cwd(opts.arg, &s);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make path '%s' absolute: %m", opts.arg);

                        path_simplify(s);

                        if (strv_consume(l, TAKE_PTR(s)) < 0)
                                return log_oom();

                        strv_uniq(*l);
                        break;
                }

                OPTION('t', "timeout", "SECS", "Block at most the specified time waiting for lock"):
                        r = parse_sec(opts.arg, &arg_timeout_usec);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --timeout= parameter: %s", opts.arg);
                        break;

                OPTION('p', "print", NULL, "Only show which block device the lock would be taken on"):
                        arg_print = true;
                        break;
                }

        char **args = option_parser_get_args(&opts);
        if (arg_print) {
                if (!strv_isempty(args))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No arguments expected.");
        } else {
                if (strv_isempty(args))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too few arguments, command to execute.");

                arg_cmdline = strv_copy(args);
                if (!arg_cmdline)
                        return log_oom();
        }

        if (strv_isempty(arg_devices) && strv_isempty(arg_backing))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No devices to lock specified, refusing.");

        return 1;
}

static int find_devno(
                dev_t **devnos,
                size_t *n_devnos,
                const char *device,
                bool backing) {

        dev_t devt;
        int r;

        assert(devnos);
        assert(n_devnos);
        assert(*devnos || *n_devnos == 0);
        assert(device);

        r = path_get_whole_disk(device, backing, &devt);
        if (r < 0)
                return log_error_errno(r, "Failed to find whole block device for '%s': %m", device);

        if (typesafe_bsearch(&devt, *devnos, *n_devnos, devt_compare_func)) {
                log_debug("Device %u:%u already listed for locking, ignoring.", major(devt), minor(devt));
                return 0;
        }

        if (!GREEDY_REALLOC(*devnos, *n_devnos + 1))
                return log_oom();

        (*devnos)[(*n_devnos)++] = devt;

        /* Immediately sort again, to ensure the binary search above will work for the next device we add */
        typesafe_qsort(*devnos, *n_devnos, devt_compare_func);
        return 1;
}

static int lock_device(
                const char *path,
                dev_t devno,
                usec_t deadline) {

        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        /* We open in O_WRONLY mode here, to trigger a rescan in udev once we are done */
        fd = open(path, O_WRONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open '%s': %m", path);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", path);

        /* Extra safety: check that the device still refers to what we think it refers to */
        if (!S_ISBLK(st.st_mode) || st.st_rdev != devno)
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO), "Path '%s' no longer refers to specified block device %u:%u.", path, major(devno), minor(devno));

        r = lock_generic(fd, LOCK_BSD, LOCK_EX|LOCK_NB);
        if (r < 0) {
                if (r != -EAGAIN)
                        return log_error_errno(r, "Failed to lock device '%s': %m", path);

                if (deadline == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Device '%s' is currently locked.", path);

                if (deadline == USEC_INFINITY)  {
                        log_info("Device '%s' is currently locked, waiting%s", path, glyph(GLYPH_ELLIPSIS));

                        r = lock_generic(fd, LOCK_BSD, LOCK_EX);
                } else {
                        usec_t left = usec_sub_unsigned(deadline, now(CLOCK_MONOTONIC));

                        log_info("Device '%s' is currently locked, waiting %s%s",
                                 path, FORMAT_TIMESPAN(left, 0),
                                 glyph(GLYPH_ELLIPSIS));

                        r = lock_generic_with_timeout(fd, LOCK_BSD, LOCK_EX, left);
                        if (r == -ETIMEDOUT)
                                return log_error_errno(r, "Timeout reached.");
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to lock device '%s': %m", path);
        }

        log_debug("Successfully locked %s (%u:%u)%s", path, major(devno), minor(devno), glyph(GLYPH_ELLIPSIS));

        return TAKE_FD(fd);
}

int verb_lock_main(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_fdset_free_ FDSet *fds = NULL;
        _cleanup_free_ dev_t *devnos = NULL;
        size_t n_devnos = 0;
        usec_t deadline;
        int r;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        STRV_FOREACH(i, arg_devices) {
                r = find_devno(&devnos, &n_devnos, *i, /* backing= */ false);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(i, arg_backing) {
                r = find_devno(&devnos, &n_devnos, *i, /* backing= */ true);
                if (r < 0)
                        return r;
        }

        assert(n_devnos > 0);

        fds = fdset_new();
        if (!fds)
                return log_oom();

        if (!timestamp_is_set(arg_timeout_usec))
                deadline = arg_timeout_usec;
        else
                deadline = usec_add(now(CLOCK_MONOTONIC), arg_timeout_usec);

        for (size_t i = 0; i < n_devnos; i++) {
                _cleanup_free_ char *node = NULL;

                r = devname_from_devnum(S_IFBLK, devnos[i], &node);
                if (r < 0)
                        return log_error_errno(r, "Failed to format block device path: %m");

                if (arg_print)
                        printf("%s\n", node);
                else {
                        _cleanup_close_ int fd = -EBADF;

                        fd = lock_device(node, devnos[i], deadline);
                        if (fd < 0)
                                return fd;

                        r = fdset_consume(fds, TAKE_FD(fd));
                        if (r < 0)
                                return log_oom();
                }
        }

        if (arg_print)
                return EXIT_SUCCESS;

        /* Ignore SIGINT and allow the forked process to receive it */
        (void) ignore_signals(SIGINT);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = pidref_safe_fork(
                        "(lock)",
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG,
                        &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */

                execvp(arg_cmdline[0], arg_cmdline);
                log_open();
                log_error_errno(errno, "Failed to execute %s: %m", arg_cmdline[0]);
                _exit(EXIT_FAILURE);
        }

        return pidref_wait_for_terminate_and_check(arg_cmdline[0], &pidref, 0);
}
