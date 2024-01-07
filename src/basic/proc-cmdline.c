/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stddef.h>

#include "alloc-util.h"
#include "efivars.h"
#include "extract-word.h"
#include "fileio.h"
#include "getopt-defs.h"
#include "initrd-util.h"
#include "macro.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "virt.h"

int proc_cmdline_filter_pid1_args(char **argv, char ***ret) {
        enum {
                COMMON_GETOPT_ARGS,
                SYSTEMD_GETOPT_ARGS,
                SHUTDOWN_GETOPT_ARGS,
        };
        static const struct option options[] = {
                COMMON_GETOPT_OPTIONS,
                SYSTEMD_GETOPT_OPTIONS,
                SHUTDOWN_GETOPT_OPTIONS,
        };
        static const char *short_options = SYSTEMD_GETOPT_SHORT_OPTIONS;

        _cleanup_strv_free_ char **filtered = NULL;
        int state, r;

        assert(argv);
        assert(ret);

        /* Currently, we do not support '-', '+', and ':' at the beginning. */
        assert(!IN_SET(short_options[0], '-', '+', ':'));

        /* Filter out all known options. */
        state = no_argument;
        STRV_FOREACH(p, strv_skip(argv, 1)) {
                int prev_state = state;
                const char *a = *p;

                /* Reset the state for the next step. */
                state = no_argument;

                if (prev_state == required_argument ||
                    (prev_state == optional_argument && a[0] != '-'))
                        /* Handled as an argument of the previous option, filtering out the string. */
                        continue;

                if (a[0] != '-') {
                        /* Not an option, accepting the string. */
                        r = strv_extend(&filtered, a);
                        if (r < 0)
                                return r;
                        continue;
                }

                if (a[1] == '-') {
                        if (a[2] == '\0') {
                                /* "--" is specified, accepting remaining strings. */
                                r = strv_extend_strv(&filtered, strv_skip(p, 1), /* filter_duplicates = */ false);
                                if (r < 0)
                                        return r;
                                break;
                        }

                        /* long option, e.g. --foo */
                        for (size_t i = 0; i < ELEMENTSOF(options); i++) {
                                const char *q = startswith(a + 2, options[i].name);
                                if (!q || !IN_SET(q[0], '=', '\0'))
                                        continue;

                                /* Found matching option, updating the state if necessary. */
                                if (q[0] == '\0' && options[i].has_arg == required_argument)
                                        state = required_argument;

                                break;
                        }
                        continue;
                }

                /* short option(s), e.g. -x or -xyz */
                while (a && *++a != '\0')
                        for (const char *q = short_options; *q != '\0'; q++) {
                                if (*q != *a)
                                        continue;

                                /* Found matching short option. */

                                if (q[1] == ':') {
                                        /* An argument is required or optional, and remaining part
                                         * is handled as argument if exists. */
                                        state = a[1] != '\0' ? no_argument :
                                                q[2] == ':' ? optional_argument : required_argument;

                                        a = NULL; /* Not necessary to parse remaining part. */
                                }
                                break;
                        }
        }

        *ret = TAKE_PTR(filtered);
        return 0;
}

int proc_cmdline(char **ret) {
        const char *e;

        assert(ret);

        /* For testing purposes it is sometimes useful to be able to override what we consider /proc/cmdline to be */
        e = secure_getenv("SYSTEMD_PROC_CMDLINE");
        if (e) {
                char *m;

                m = strdup(e);
                if (!m)
                        return -ENOMEM;

                *ret = m;
                return 0;
        }

        if (detect_container() > 0)
                return pid_get_cmdline(1, SIZE_MAX, 0, ret);
        
        void* voidPtr = *ret;
        return read_virtual_file("/proc/cmdline", SIZE_MAX, &voidPtr, NULL);
}

static int proc_cmdline_strv_internal(char ***ret, bool filter_pid1_args) {
        const char *e;
        int r;

        assert(ret);

        /* For testing purposes it is sometimes useful to be able to override what we consider /proc/cmdline to be */
        e = secure_getenv("SYSTEMD_PROC_CMDLINE");
        if (e)
                return strv_split_full(ret, e, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);

        if (detect_container() > 0) {
                _cleanup_strv_free_ char **args = NULL;

                r = pid_get_cmdline_strv(1, /* flags = */ 0, &args);
                if (r < 0)
                        return r;

                if (filter_pid1_args)
                        return proc_cmdline_filter_pid1_args(args, ret);

                *ret = TAKE_PTR(args);
                return 0;

        } else {
                _cleanup_free_ void *s = NULL;

                r = read_full_file("/proc/cmdline", &s, NULL);
                if (r < 0)
                        return r;

                return strv_split_full(ret, s, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);
        }
}

int proc_cmdline_strv(char ***ret) {
        return proc_cmdline_strv_internal(ret, /* filter_pid1_args = */ false);
}

static char *mangle_word(const char *word, ProcCmdlineFlags flags) {
        char *c;

        c = startswith(word, "rd.");
        if (c) {
                /* Filter out arguments that are intended only for the initrd */

                if (!in_initrd())
                        return NULL;

                if (FLAGS_SET(flags, PROC_CMDLINE_STRIP_RD_PREFIX))
                        return c;

        } else if (FLAGS_SET(flags, PROC_CMDLINE_RD_STRICT) && in_initrd())
                /* And optionally filter out arguments that are intended only for the host */
                return NULL;

        return (char*) word;
}

static int proc_cmdline_parse_strv(char **args, proc_cmdline_parse_t parse_item, void *data, ProcCmdlineFlags flags) {
        int r;

        assert(parse_item);

        STRV_FOREACH(word, args) {
                char *key, *value;

                key = mangle_word(*word, flags);
                if (!key)
                        continue;

                value = strchr(key, '=');
                if (value)
                        *(value++) = '\0';

                r = parse_item(key, value, data);
                if (r < 0)
                        return r;
        }

        return 0;
}

int proc_cmdline_parse(proc_cmdline_parse_t parse_item, void *data, ProcCmdlineFlags flags) {
        _cleanup_strv_free_ char **args = NULL;
        int r;

        assert(parse_item);

        /* The PROC_CMDLINE_VALUE_OPTIONAL and PROC_CMDLINE_TRUE_WHEN_MISSING flags don't really make sense
         * for proc_cmdline_parse(), let's make this clear. */
        assert(!(flags & (PROC_CMDLINE_VALUE_OPTIONAL|PROC_CMDLINE_TRUE_WHEN_MISSING)));

        /* We parse the EFI variable first, because later settings have higher priority. */

        if (!FLAGS_SET(flags, PROC_CMDLINE_IGNORE_EFI_OPTIONS)) {
                _cleanup_free_ char *line = NULL;

                r = systemd_efi_options_variable(&line);
                if (r < 0) {
                        if (r != -ENODATA)
                                log_debug_errno(r, "Failed to get SystemdOptions EFI variable, ignoring: %m");
                } else {
                        r = strv_split_full(&args, line, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return r;

                        r = proc_cmdline_parse_strv(args, parse_item, data, flags);
                        if (r < 0)
                                return r;

                        args = strv_free(args);
                }
        }

        r = proc_cmdline_strv_internal(&args, /* filter_pid1_args = */ true);
        if (r < 0)
                return r;

        return proc_cmdline_parse_strv(args, parse_item, data, flags);
}

static bool relaxed_equal_char(char a, char b) {
        return a == b ||
                (a == '_' && b == '-') ||
                (a == '-' && b == '_');
}

char *proc_cmdline_key_startswith(const char *s, const char *prefix) {
        assert(s);
        assert(prefix);

        /* Much like startswith(), but considers "-" and "_" the same */

        for (; *prefix != 0; s++, prefix++)
                if (!relaxed_equal_char(*s, *prefix))
                        return NULL;

        return (char*) s;
}

bool proc_cmdline_key_streq(const char *x, const char *y) {
        assert(x);
        assert(y);

        /* Much like streq(), but considers "-" and "_" the same */

        for (; *x != 0 || *y != 0; x++, y++)
                if (!relaxed_equal_char(*x, *y))
                        return false;

        return true;
}

static int cmdline_get_key(char **args, const char *key, ProcCmdlineFlags flags, char **ret_value) {
        _cleanup_free_ char *v = NULL;
        bool found = false;
        int r;

        assert(key);

        STRV_FOREACH(p, args) {
                const char *word;

                word = mangle_word(*p, flags);
                if (!word)
                        continue;

                if (ret_value) {
                        const char *e;

                        e = proc_cmdline_key_startswith(word, key);
                        if (!e)
                                continue;

                        if (*e == '=') {
                                r = free_and_strdup(&v, e+1);
                                if (r < 0)
                                        return r;

                                found = true;

                        } else if (*e == 0 && FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL))
                                found = true;

                } else {
                        if (proc_cmdline_key_streq(word, key)) {
                                found = true;
                                break; /* we found what we were looking for */
                        }
                }
        }

        if (ret_value)
                *ret_value = TAKE_PTR(v);

        return found;
}

int proc_cmdline_get_key(const char *key, ProcCmdlineFlags flags, char **ret_value) {
        _cleanup_strv_free_ char **args = NULL;
        _cleanup_free_ char *line = NULL, *v = NULL;
        int r;

        /* Looks for a specific key on the kernel command line and (with lower priority) the EFI variable.
         * Supports three modes:
         *
         * a) The "ret_value" parameter is used. In this case a parameter beginning with the "key" string followed by
         *    "=" is searched for, and the value following it is returned in "ret_value".
         *
         * b) as above, but the PROC_CMDLINE_VALUE_OPTIONAL flag is set. In this case if the key is found as a separate
         *    word (i.e. not followed by "=" but instead by whitespace or the end of the command line), then this is
         *    also accepted, and "value" is returned as NULL.
         *
         * c) The "ret_value" parameter is NULL. In this case a search for the exact "key" parameter is performed.
         *
         * In all three cases, > 0 is returned if the key is found, 0 if not. */

        /* PROC_CMDLINE_TRUE_WHEN_MISSING doesn't really make sense for proc_cmdline_get_key(). */
        assert(!FLAGS_SET(flags, PROC_CMDLINE_TRUE_WHEN_MISSING));

        if (isempty(key))
                return -EINVAL;

        if (FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL) && !ret_value)
                return -EINVAL;

        r = proc_cmdline_strv_internal(&args, /* filter_pid1_args = */ true);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, PROC_CMDLINE_IGNORE_EFI_OPTIONS)) /* Shortcut */
                return cmdline_get_key(args, key, flags, ret_value);

        r = cmdline_get_key(args, key, flags, ret_value ? &v : NULL);
        if (r < 0)
                return r;
        if (r > 0) {
                if (ret_value)
                        *ret_value = TAKE_PTR(v);

                return r;
        }

        r = systemd_efi_options_variable(&line);
        if (r == -ENODATA) {
                if (ret_value)
                        *ret_value = NULL;

                return false; /* Not found */
        }
        if (r < 0)
                return r;

        args = strv_free(args);
        r = strv_split_full(&args, line, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);
        if (r < 0)
                return r;

        return cmdline_get_key(args, key, flags, ret_value);
}

int proc_cmdline_get_bool(const char *key, ProcCmdlineFlags flags, bool *ret) {
        _cleanup_free_ char *v = NULL;
        int r;

        assert(ret);

        r = proc_cmdline_get_key(key, (flags & ~PROC_CMDLINE_TRUE_WHEN_MISSING) | PROC_CMDLINE_VALUE_OPTIONAL, &v);
        if (r < 0)
                return r;
        if (r == 0) { /* key not specified at all */
                *ret = FLAGS_SET(flags, PROC_CMDLINE_TRUE_WHEN_MISSING);
                return 0;
        }

        if (v) { /* key with parameter passed */
                r = parse_boolean(v);
                if (r < 0)
                        return r;
                *ret = r;
        } else /* key without parameter passed */
                *ret = true;

        return 1;
}

static int cmdline_get_key_ap(ProcCmdlineFlags flags, char* const* args, va_list ap) {
        int r, ret = 0;

        for (;;) {
                char **v;
                const char *k, *e;

                k = va_arg(ap, const char*);
                if (!k)
                        break;

                assert_se(v = va_arg(ap, char**));

                STRV_FOREACH(p, args) {
                        const char *word;

                        word = mangle_word(*p, flags);
                        if (!word)
                                continue;

                        e = proc_cmdline_key_startswith(word, k);
                        if (e && *e == '=') {
                                r = free_and_strdup(v, e + 1);
                                if (r < 0)
                                        return r;

                                ret++;
                        }
                }
        }

        return ret;
}

int proc_cmdline_get_key_many_internal(ProcCmdlineFlags flags, ...) {
        _cleanup_strv_free_ char **args = NULL;
        int r, ret = 0;
        va_list ap;

        /* The PROC_CMDLINE_VALUE_OPTIONAL and PROC_CMDLINE_TRUE_WHEN_MISSING flags don't really make sense
         * for proc_cmdline_get_key_many, let's make this clear. */
        assert(!(flags & (PROC_CMDLINE_VALUE_OPTIONAL|PROC_CMDLINE_TRUE_WHEN_MISSING)));

        /* This call may clobber arguments on failure! */

        if (!FLAGS_SET(flags, PROC_CMDLINE_IGNORE_EFI_OPTIONS)) {
                _cleanup_free_ char *line = NULL;

                r = systemd_efi_options_variable(&line);
                if (r < 0 && r != -ENODATA)
                        log_debug_errno(r, "Failed to get SystemdOptions EFI variable, ignoring: %m");
                if (r >= 0) {
                        r = strv_split_full(&args, line, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);
                        if (r < 0)
                                return r;

                        va_start(ap, flags);
                        r = cmdline_get_key_ap(flags, args, ap);
                        va_end(ap);
                        if (r < 0)
                                return r;

                        ret = r;
                        args = strv_free(args);
                }
        }

        r = proc_cmdline_strv(&args);
        if (r < 0)
                return r;

        va_start(ap, flags);
        r = cmdline_get_key_ap(flags, args, ap);
        va_end(ap);
        if (r < 0)
                return r;

        return ret + r;
}
