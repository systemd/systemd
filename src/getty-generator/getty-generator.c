/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "creds-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "initrd-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-name.h"
#include "virt.h"

static const char *arg_dest = NULL;
static bool arg_enabled = true;

static int add_symlink(const char *fservice, const char *tservice) {
        const char *from, *to;

        assert(fservice);
        assert(tservice);

        from = strjoina(SYSTEM_DATA_UNIT_DIR "/", fservice);
        to = strjoina(arg_dest, "/getty.target.wants/", tservice);

        (void) mkdir_parents_label(to, 0755);

        if (symlink(from, to) < 0) {
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
        _cleanup_close_ int fd = -EBADF;
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

        if (!isatty_safe(fd))
                return -errno;

        return 0;
}

static int run_container(void) {
        _cleanup_free_ char *container_ttys = NULL;
        int r;

        log_debug("Automatically adding console shell.");

        r = add_symlink("console-getty.service", "console-getty.service");
        if (r < 0)
                return r;

        /* When $container_ttys is set for PID 1, spawn gettys on all ptys named therein.
         * Note that despite the variable name we only support ptys here. */

        (void) getenv_for_pid(1, "container_ttys", &container_ttys);

        for (const char *p = container_ttys;;) {
               _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $container_ttys: %m");
                if (r == 0)
                        return 0;

                const char *tty = word;

                /* First strip off /dev/ if it is specified */
                tty = path_startswith(tty, "/dev/") ?: tty;

                /* Then, make sure it's actually a pty */
                tty = path_startswith(tty, "pts/");
                if (!tty)
                        continue;

                r = add_container_getty(tty);
                if (r < 0)
                        return r;
        }
}

static int add_credential_gettys(void) {
        static const struct {
                const char *credential_name;
                int (*func)(const char *tty);
        } table[] = {
                { "getty.ttys.serial",    add_serial_getty     },
                { "getty.ttys.container", add_container_getty  },
        };
        int r;

        FOREACH_ARRAY(t, table, ELEMENTSOF(table)) {
                _cleanup_free_ char *b = NULL;
                size_t sz = 0;

                r = read_credential_with_decryption(t->credential_name, (void*) &b, &sz);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                _cleanup_fclose_ FILE *f = NULL;
                f = fmemopen_unlocked(b, sz, "r");
                if (!f)
                        return log_oom();

                for (;;) {
                        _cleanup_free_ char *tty = NULL;

                        r = read_stripped_line(f, PATH_MAX, &tty);
                        if (r == 0)
                                break;
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse credential %s: %m", t->credential_name);
                                break;
                        }

                        if (startswith(tty, "#"))
                                continue;

                        r = t->func(tty);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "systemd.getty_auto")) {
                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning_errno(r, "Failed to parse getty_auto switch \"%s\", ignoring: %m", value);
                else
                        arg_enabled = r;
        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        _cleanup_free_ char *getty_auto = NULL;
        int r;

        assert_se(arg_dest = dest);

        if (in_initrd()) {
                log_debug("Skipping generator, running in the initrd.");
                return EXIT_SUCCESS;
        }

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        r = getenv_for_pid(1, "SYSTEMD_GETTY_AUTO", &getty_auto);
        if (r < 0)
                log_warning_errno(r, "Failed to parse $SYSTEMD_GETTY_AUTO environment variable, ignoring: %m");
        else if (r > 0) {
                r = parse_boolean(getty_auto);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_GETTY_AUTO value \"%s\", ignoring: %m", getty_auto);
                else
                        arg_enabled = r;
        }

        if (!arg_enabled) {
                log_debug("Disabled, exiting.");
                return 0;
        }

        r = add_credential_gettys();
        if (r < 0)
                return r;

        if (detect_container() > 0)
                /* Add console shell and look at $container_ttys, but don't do add any
                 * further magic if we are in a container. */
                return run_container();

        /* Automatically add in a serial getty on all active kernel consoles */
        _cleanup_free_ char *active = NULL;
        (void) read_one_line_file("/sys/class/tty/console/active", &active);
        for (const char *p = active;;) {
               _cleanup_free_ char *tty = NULL;

                r = extract_first_word(&p, &tty, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse /sys/class/tty/console/active: %m");
                if (r == 0)
                        break;

                /* We assume that gettys on virtual terminals are started via manual configuration and do
                 * this magic only for non-VC terminals. */

                if (isempty(tty) || tty_is_vc(tty))
                        continue;

                if (verify_tty(tty) < 0)
                        continue;

                r = add_serial_getty(tty);
                if (r < 0)
                        return r;
        }

        /* Automatically add in a serial getty on the first virtualizer console */
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
                        return log_oom();
                if (access(p, F_OK) < 0)
                        continue;

                r = add_serial_getty(j);
                if (r < 0)
                        return r;
        }

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
