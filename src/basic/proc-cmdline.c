/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>

#include "alloc-util.h"
#include "efivars.h"
#include "extract-word.h"
#include "fileio.h"
#include "initrd-util.h"
#include "macro.h"
#include "parse-util.h"
#include "proc-cmdline-internal.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
#include "virt.h"

static void filter_pid1_args(
                int argc,                /* input */
                char **argv,             /* input, may be reordered by this function, should not be reused. */
                const char **filtered) { /* optput */

        int saved_optind, saved_opterr, saved_optopt, r;
        char *saved_optarg;
        size_t n = 0;

        assert(argc > 0);
        assert(argv);
        assert(filtered);

        saved_optind = optind;
        saved_opterr = opterr;
        saved_optopt = optopt;
        saved_optarg = optarg;

        optind = 1;
        opterr = 0;

        /* Filter out all known options. */
        while ((r = getopt_long(argc, argv, SYSTEMD_GETOPT_SHORT_OPTIONS, systemd_getopt_options, NULL)) >= 0)
                ;

        /* Also filter all strings start with '-'. */
        for (int i = optind; i < argc; i++) {
                if (argv[i][0] == '-')
                        continue;

                filtered[n++] = argv[i];
        }

        /* Make the result valid strv. */
        filtered[n] = NULL;

        optind = saved_optind;
        opterr = saved_opterr;
        optopt = saved_optopt;
        optarg = saved_optarg;
}

int proc_cmdline_filter_pid1_args(const char *s, char **ret) {
        _cleanup_strv_free_ char **args = NULL;
        _cleanup_free_ const char **filtered = NULL;
        char *joined;
        int r;

        assert(s);
        assert(ret);

        /* Here, we need to keep quotes, otherwise, the result string will be wrongly parsed by
         * proc_cmdline_extract_first(). We assume that the arguments that should be filtered by
         * filter_pid1_args() are not quoted. */
        r = strv_split_full(&args, s, NULL, EXTRACT_KEEP_QUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);
        if (r < 0)
                return r;

        /* filter_pid1_args() always cut the first argument, hence +1 is not necessary. */
        filtered = new(const char*, r);
        if (!filtered)
                return -ENOMEM;

        filter_pid1_args(r, args, filtered);

        joined = strv_join((char* const*) filtered, " ");
        if (!joined)
                return -ENOMEM;

        *ret = joined;
        return 0;
}

int proc_cmdline(char **ret) {
        const char *e;
        int r;

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

        if (detect_container() > 0) {
                _cleanup_free_ char *s = NULL;

                /* When we are running in a container, then the command line may contain the positional
                 * arguments that should be parsed by PID1, e.g. deserialized FD or so, let's filter them. */

                r = get_process_cmdline(1, SIZE_MAX, 0, &s);
                if (r < 0)
                        return r;

                return proc_cmdline_filter_pid1_args(s, ret);
        }

        return read_one_line_file("/proc/cmdline", ret);
}

static int proc_cmdline_extract_first(const char **p, char **ret_word, ProcCmdlineFlags flags) {
        const char *q = *p;
        int r;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                const char *c;

                r = extract_first_word(&q, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Filter out arguments that are intended only for the initrd */
                c = startswith(word, "rd.");
                if (c) {
                        if (!in_initrd())
                                continue;

                        if (FLAGS_SET(flags, PROC_CMDLINE_STRIP_RD_PREFIX)) {
                                r = free_and_strdup(&word, c);
                                if (r < 0)
                                        return r;
                        }

                } else if (FLAGS_SET(flags, PROC_CMDLINE_RD_STRICT) && in_initrd())
                        continue; /* And optionally filter out arguments that are intended only for the host */

                *p = q;
                *ret_word = TAKE_PTR(word);
                return 1;
        }

        *p = q;
        *ret_word = NULL;
        return 0;
}

int proc_cmdline_parse_given(const char *line, proc_cmdline_parse_t parse_item, void *data, ProcCmdlineFlags flags) {
        const char *p;
        int r;

        assert(parse_item);

        /* The PROC_CMDLINE_VALUE_OPTIONAL flag doesn't really make sense for proc_cmdline_parse(), let's make this
         * clear. */
        assert(!FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL));

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *value;

                r = proc_cmdline_extract_first(&p, &word, flags);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                value = strchr(word, '=');
                if (value)
                        *(value++) = 0;

                r = parse_item(word, value, data);
                if (r < 0)
                        return r;
        }

        return 0;
}

int proc_cmdline_parse(proc_cmdline_parse_t parse_item, void *data, ProcCmdlineFlags flags) {
        _cleanup_free_ char *line = NULL;
        int r;

        assert(parse_item);

        /* We parse the EFI variable first, because later settings have higher priority. */

        if (!FLAGS_SET(flags, PROC_CMDLINE_IGNORE_EFI_OPTIONS)) {
                r = systemd_efi_options_variable(&line);
                if (r < 0) {
                        if (r != -ENODATA)
                                log_debug_errno(r, "Failed to get SystemdOptions EFI variable, ignoring: %m");
                } else {
                        r = proc_cmdline_parse_given(line, parse_item, data, flags);
                        if (r < 0)
                                return r;

                        line = mfree(line);
                }
        }

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        return proc_cmdline_parse_given(line, parse_item, data, flags);
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

static int cmdline_get_key(const char *line, const char *key, ProcCmdlineFlags flags, char **ret_value) {
        _cleanup_free_ char *ret = NULL;
        bool found = false;
        const char *p;
        int r;

        assert(line);
        assert(key);

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = proc_cmdline_extract_first(&p, &word, flags);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (ret_value) {
                        const char *e;

                        e = proc_cmdline_key_startswith(word, key);
                        if (!e)
                                continue;

                        if (*e == '=') {
                                r = free_and_strdup(&ret, e+1);
                                if (r < 0)
                                        return r;

                                found = true;

                        } else if (*e == 0 && FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL))
                                found = true;

                } else {
                        if (streq(word, key)) {
                                found = true;
                                break; /* we found what we were looking for */
                        }
                }
        }

        if (ret_value)
                *ret_value = TAKE_PTR(ret);

        return found;
}

int proc_cmdline_get_key(const char *key, ProcCmdlineFlags flags, char **ret_value) {
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

        if (isempty(key))
                return -EINVAL;

        if (FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL) && !ret_value)
                return -EINVAL;

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, PROC_CMDLINE_IGNORE_EFI_OPTIONS)) /* Shortcut */
                return cmdline_get_key(line, key, flags, ret_value);

        r = cmdline_get_key(line, key, flags, ret_value ? &v : NULL);
        if (r < 0)
                return r;
        if (r > 0) {
                if (ret_value)
                        *ret_value = TAKE_PTR(v);

                return r;
        }

        line = mfree(line);
        r = systemd_efi_options_variable(&line);
        if (r == -ENODATA) {
                if (ret_value)
                        *ret_value = NULL;

                return false; /* Not found */
        }
        if (r < 0)
                return r;

        return cmdline_get_key(line, key, flags, ret_value);
}

int proc_cmdline_get_bool(const char *key, bool *ret) {
        _cleanup_free_ char *v = NULL;
        int r;

        assert(ret);

        r = proc_cmdline_get_key(key, PROC_CMDLINE_VALUE_OPTIONAL, &v);
        if (r < 0)
                return r;
        if (r == 0) { /* key not specified at all */
                *ret = false;
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

int proc_cmdline_get_key_many_internal(ProcCmdlineFlags flags, ...) {
        _cleanup_free_ char *line = NULL;
        bool processing_efi = true;
        const char *p;
        va_list ap;
        int r, ret = 0;

        /* The PROC_CMDLINE_VALUE_OPTIONAL flag doesn't really make sense for proc_cmdline_get_key_many(), let's make
         * this clear. */
        assert(!FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL));

        /* This call may clobber arguments on failure! */

        if (!FLAGS_SET(flags, PROC_CMDLINE_IGNORE_EFI_OPTIONS)) {
                r = systemd_efi_options_variable(&line);
                if (r < 0 && r != -ENODATA)
                        log_debug_errno(r, "Failed to get SystemdOptions EFI variable, ignoring: %m");
        }

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = proc_cmdline_extract_first(&p, &word, flags);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* We finished with this command line. If this was the EFI one, then let's proceed with the regular one */
                        if (processing_efi) {
                                processing_efi = false;

                                line = mfree(line);
                                r = proc_cmdline(&line);
                                if (r < 0)
                                        return r;

                                p = line;
                                continue;
                        }

                        break;
                }

                va_start(ap, flags);

                for (;;) {
                        char **v;
                        const char *k, *e;

                        k = va_arg(ap, const char*);
                        if (!k)
                                break;

                        assert_se(v = va_arg(ap, char**));

                        e = proc_cmdline_key_startswith(word, k);
                        if (e && *e == '=') {
                                r = free_and_strdup(v, e + 1);
                                if (r < 0) {
                                        va_end(ap);
                                        return r;
                                }

                                ret++;
                        }
                }

                va_end(ap);
        }

        return ret;
}
