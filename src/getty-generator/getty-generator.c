/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "creds-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "initrd-util.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "unit-name.h"
#include "virt.h"

typedef enum {
        GETTY_SOURCE_NONE       = 0,
        GETTY_SOURCE_CREDENTIAL = 1 << 0,
        GETTY_SOURCE_CONTAINER  = 1 << 1,
        GETTY_SOURCE_CONSOLE    = 1 << 2,
        GETTY_SOURCE_BUILTIN    = 1 << 3,
        GETTY_SOURCE_ALL        = GETTY_SOURCE_CREDENTIAL | GETTY_SOURCE_CONTAINER | GETTY_SOURCE_CONSOLE | GETTY_SOURCE_BUILTIN,
} GettySourceFlag;

static const char *arg_dest = NULL;
static GettySourceFlag arg_getty_sources = GETTY_SOURCE_ALL;

static int add_getty_impl(const char *tty, const char *path, const char *type, const char *unit_path) {
        int r;

        assert(type);
        assert(path);
        assert(unit_path);

        if (!filename_is_valid(tty)) {
                log_debug("Invalid %s tty device specified, ignoring: %s", type, path);
                return 0;
        }

        _cleanup_free_ char *instance = NULL;
        r = unit_name_path_escape(tty, &instance);
        if (r < 0)
                return log_error_errno(r, "Failed to escape %s tty path %s: %m", type, tty);

        log_debug("Automatically adding %s getty for %s.", type, tty);

        return generator_add_symlink_full(arg_dest, "getty.target", "wants", unit_path, instance);
}

static int add_serial_getty(const char *path) {
        const char *tty = skip_dev_prefix(ASSERT_PTR(path));
        return add_getty_impl(tty, path, "serial", SYSTEM_DATA_UNIT_DIR "/serial-getty@.service");
}

static int add_container_getty(const char *tty_or_path) {
        const char *tty;

        assert(tty_or_path);

        if (is_path(tty_or_path))
                /* Check if it is actually a pty. */
                tty = path_startswith(skip_dev_prefix(tty_or_path), "pts/");
        else
                tty = tty_or_path;

        return add_getty_impl(tty, tty_or_path, "container", SYSTEM_DATA_UNIT_DIR "/container-getty@.service");
}

static int verify_tty(const char *path) {
        _cleanup_close_ int fd = -EBADF;

        assert(path);

        /* Some TTYs are weird and have been enumerated but don't work when you try to use them, such as
         * classic ttyS0 and friends. Let's check that and open the device and run isatty() on it. */

        /* O_NONBLOCK is essential here, to make sure we don't wait for DCD */
        fd = open(path, O_RDWR|O_NONBLOCK|O_NOCTTY|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        if (!isatty_safe(fd))
                return -ENOTTY;

        return 0;
}

static int run_container(void) {
        int r;

        log_debug("Automatically adding console shell.");

        r = generator_add_symlink(arg_dest, "getty.target", "wants", SYSTEM_DATA_UNIT_DIR "/console-getty.service");
        if (r < 0)
                return r;

        /* When $container_ttys is set for PID 1, spawn gettys on all ptys named therein.
         * Note that despite the variable name we only support ptys here. */
        _cleanup_free_ char *container_ttys = NULL;
        (void) getenv_for_pid(1, "container_ttys", &container_ttys);

        for (const char *p = container_ttys;;) {
               _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $container_ttys: %m");
                if (r == 0)
                        return 0;

                /* add_container_getty() also accepts a filename, but here we request that the string
                 * contains "pts/". */
                if (!is_path(word))
                        continue;

                r = add_container_getty(word);
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

        log_debug("Checking credentials for configuration...");

        FOREACH_ELEMENT(t, table) {
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

static int parse_getty_sources(const char *s, GettySourceFlag *ret) {
        int r;

        assert(ret);

        if (isempty(s)) {
                *ret = GETTY_SOURCE_ALL;
                return 0;
        }

        r = parse_boolean(s);
        if (r >= 0) {
                *ret = r ? GETTY_SOURCE_ALL : GETTY_SOURCE_NONE;
                return 0;
        }

        static struct {
                GettySourceFlag flag;
                const char *str;
        } table[] = {
                { GETTY_SOURCE_CREDENTIAL, "credential", },
                { GETTY_SOURCE_CONTAINER,  "container",  },
                { GETTY_SOURCE_CONSOLE,    "console",    },
                { GETTY_SOURCE_BUILTIN,    "builtin",    },
        };

        GettySourceFlag flags = 0;
        for (const char *p = s;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", /* flags = */ 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                bool found = false;
                FOREACH_ELEMENT(i, table)
                        if (streq(word, i->str)) {
                                flags |= i->flag;
                                found = true;
                                break;
                        }

                if (!found)
                        return -EINVAL;
        }

        *ret = flags;
        return 0;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        if (proc_cmdline_key_streq(key, "systemd.getty_auto")) {
                r = parse_getty_sources(value, &arg_getty_sources);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse systemd.getty_auto= kernel command line option, ignoring: %s", value);
        }

        return 0;
}

static void parse_env(void) {
        _cleanup_free_ char *value = NULL;
        int r;

        r = getenv_for_pid(1, "SYSTEMD_GETTY_AUTO", &value);
        if (r < 0)
                log_warning_errno(r, "Failed to read $SYSTEMD_GETTY_AUTO in PID 1's environment, ignoring: %m");
        else if (r > 0) {
                r = parse_getty_sources(value, &arg_getty_sources);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_GETTY_AUTO from PID 1's environment, ignoring: %s",
                                          value);
        }
}

static void parse_credentials(void) {
        _cleanup_free_ char *value = NULL;
        int r;

        r = read_credential_with_decryption("getty.auto", (void**) &value, /* ret_size = */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential 'getty.auto', ignoring: %m");
        else if (r > 0) {
                r = parse_getty_sources(value, &arg_getty_sources);
                if (r < 0)
                        log_warning_errno(r, "Invalid 'getty.auto' credential, ignoring: %s", value);
        }
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        assert_se(arg_dest = dest);

        if (in_initrd()) {
                log_debug("Skipping generator, running in the initrd.");
                return EXIT_SUCCESS;
        }

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        parse_env();
        parse_credentials();

        if (arg_getty_sources == GETTY_SOURCE_NONE) {
                log_debug("Disabled, exiting.");
                return 0;
        }

        if (FLAGS_SET(arg_getty_sources, GETTY_SOURCE_CREDENTIAL)) {
                r = add_credential_gettys();
                if (r < 0)
                        return r;
        }

        if (detect_container() > 0) {
                /* Add console shell and look at $container_ttys, but don't do add any
                 * further magic if we are in a container. */
                if (FLAGS_SET(arg_getty_sources, GETTY_SOURCE_CONTAINER))
                        return run_container();

                return 0;
        }

        /* Automatically add in a serial getty on all active kernel consoles */
        if (FLAGS_SET(arg_getty_sources, GETTY_SOURCE_CONSOLE)) {
                _cleanup_strv_free_ char **consoles = NULL;
                r = get_kernel_consoles(&consoles);
                if (r < 0)
                        log_warning_errno(r, "Failed to get active kernel consoles, ignoring: %m");
                else if (r > 0)
                        STRV_FOREACH(i, consoles) {
                                /* We assume that gettys on virtual terminals are started via manual
                                 * configuration and do this magic only for non-VC terminals. */
                                if (tty_is_vc(*i))
                                        continue;

                                if (verify_tty(*i) < 0)
                                        continue;

                                r = add_serial_getty(*i);
                                if (r < 0)
                                        return r;
                        }
        }

        /* Automatically add a serial getty to each available virtualizer console. */
        if (FLAGS_SET(arg_getty_sources, GETTY_SOURCE_BUILTIN))
                FOREACH_STRING(j,
                               "hvc0",
                               "xvc0",
                               "hvsi0",
                               "sclp_line0",
                               "ttysclp0",
                               "3270/tty1") {
                        _cleanup_free_ char *p = NULL;

                        p = path_join("/dev", j);
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
