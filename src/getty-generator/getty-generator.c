/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "log.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-name.h"
#include "util.h"
#include "virt.h"

static const char *arg_dest = NULL;

static int add_symlink(const char *fservice, const char *tservice) {
        char *from, *to;
        int r;

        assert(fservice);
        assert(tservice);

        from = strjoina(SYSTEM_DATA_UNIT_PATH "/", fservice);
        to = strjoina(arg_dest, "/getty.target.wants/", tservice);

        mkdir_parents_label(to, 0755);

        r = symlink(from, to);
        if (r < 0) {
                /* In case console=hvc0 is passed this will very likely result in EEXIST */
                if (errno == EEXIST)
                        return 0;

                return log_error_errno(errno, "Failed to create symlink %s: %m", to);
        }

        return 0;
}

static int add_serial_getty(const char *tty) {
        _cleanup_free_ char *n = NULL;
        int r;

        assert(tty);

        log_debug("Automatically adding serial getty for /dev/%s.", tty);

        r = unit_name_from_path_instance("serial-getty", tty, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate service name: %m");

        return add_symlink("serial-getty@.service", n);
}

static int add_container_getty(const char *tty) {
        _cleanup_free_ char *n = NULL;
        int r;

        assert(tty);

        log_debug("Automatically adding container getty for /dev/pts/%s.", tty);

        r = unit_name_from_path_instance("container-getty", tty, ".service", &n);
        if (r < 0)
                return log_error_errno(r, "Failed to generate service name: %m");

        return add_symlink("container-getty@.service", n);
}

static int verify_tty(const char *name) {
        _cleanup_close_ int fd = -1;
        const char *p;

        /* Some TTYs are weird and have been enumerated but don't work
         * when you try to use them, such as classic ttyS0 and
         * friends. Let's check that and open the device and run
         * isatty() on it. */

        p = strjoina("/dev/", name);

        /* O_NONBLOCK is essential here, to make sure we don't wait
         * for DCD */
        fd = open(p, O_RDWR|O_NONBLOCK|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        errno = 0;
        if (isatty(fd) <= 0)
                return errno_or_else(EIO);

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        _cleanup_free_ char *active = NULL;
        const char *j;
        int r;

        assert_se(arg_dest = dest);

        if (detect_container() > 0) {
                _cleanup_free_ char *container_ttys = NULL;

                log_debug("Automatically adding console shell.");

                r = add_symlink("console-getty.service", "console-getty.service");
                if (r < 0)
                        return r;

                /* When $container_ttys is set for PID 1, spawn
                 * gettys on all ptys named therein. Note that despite
                 * the variable name we only support ptys here. */

                r = getenv_for_pid(1, "container_ttys", &container_ttys);
                if (r > 0) {
                        const char *word, *state;
                        size_t l;

                        FOREACH_WORD(word, l, container_ttys, state) {
                                const char *t;
                                char tty[l + 1];

                                memcpy(tty, word, l);
                                tty[l] = 0;

                                /* First strip off /dev/ if it is specified */
                                t = path_startswith(tty, "/dev/");
                                if (!t)
                                        t = tty;

                                /* Then, make sure it's actually a pty */
                                t = path_startswith(t, "pts/");
                                if (!t)
                                        continue;

                                r = add_container_getty(t);
                                if (r < 0)
                                        return r;
                        }
                }

                /* Don't add any further magic if we are in a container */
                return 0;
        }

        if (read_one_line_file("/sys/class/tty/console/active", &active) >= 0) {
                const char *word, *state;
                size_t l;

                /* Automatically add in a serial getty on all active
                 * kernel consoles */
                FOREACH_WORD(word, l, active, state) {
                        _cleanup_free_ char *tty = NULL;

                        tty = strndup(word, l);
                        if (!tty)
                                return log_oom();

                        /* We assume that gettys on virtual terminals are
                         * started via manual configuration and do this magic
                         * only for non-VC terminals. */

                        if (isempty(tty) || tty_is_vc(tty))
                                continue;

                        if (verify_tty(tty) < 0)
                                continue;

                        r = add_serial_getty(tty);
                        if (r < 0)
                                return r;
                }
        }

        /* Automatically add in a serial getty on the first
         * virtualizer console */
        FOREACH_STRING(j,
                       "hvc0",
                       "xvc0",
                       "hvsi0",
                       "sclp_line0",
                       "ttysclp0",
                       "3270!tty1") {
                _cleanup_free_ char *p = NULL;

                p = path_join("/sys/class/tty", j);
                if (!p)
                        return -ENOMEM;
                if (access(p, F_OK) < 0)
                        continue;

                r = add_serial_getty(j);
                if (r < 0)
                        return r;
        }

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
