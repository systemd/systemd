/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "macro.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "special.h"
#include "string-util.h"
#include "util.h"
#include "virt.h"

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
                return get_process_cmdline(1, SIZE_MAX, 0, ret);
        else
                return read_one_line_file("/proc/cmdline", ret);
}

static int proc_cmdline_extract_first(const char **p, char **ret_word, ProcCmdlineFlags flags) {
        const char *q = *p;
        int r;

        for (;;) {
                _cleanup_free_ char *word = NULL;
                const char *c;

                r = extract_first_word(&q, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX);
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

int proc_cmdline_get_key(const char *key, ProcCmdlineFlags flags, char **ret_value) {
        _cleanup_free_ char *line = NULL, *ret = NULL;
        bool found = false;
        const char *p;
        int r;

        /* Looks for a specific key on the kernel command line. Supports three modes:
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

int proc_cmdline_get_bool(const char *key, bool *ret) {
        _cleanup_free_ char *v = NULL;
        int r;

        assert(ret);

        r = proc_cmdline_get_key(key, PROC_CMDLINE_VALUE_OPTIONAL, &v);
        if (r < 0)
                return r;
        if (r == 0) {
                *ret = false;
                return 0;
        }

        if (v) { /* parameter passed */
                r = parse_boolean(v);
                if (r < 0)
                        return r;
                *ret = r;
        } else /* no parameter passed */
                *ret = true;

        return 1;
}

int proc_cmdline_get_key_many_internal(ProcCmdlineFlags flags, ...) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        va_list ap;
        int r, ret = 0;

        /* The PROC_CMDLINE_VALUE_OPTIONAL flag doesn't really make sense for proc_cmdline_get_key_many(), let's make
         * this clear. */
        assert(!FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL));

        /* This call may clobber arguments on failure! */

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = proc_cmdline_extract_first(&p, &word, flags);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

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

int shall_restore_state(void) {
        bool ret;
        int r;

        r = proc_cmdline_get_bool("systemd.restore_state", &ret);
        if (r < 0)
                return r;

        return r > 0 ? ret : true;
}

static const char * const rlmap[] = {
        "emergency", SPECIAL_EMERGENCY_TARGET,
        "-b",        SPECIAL_EMERGENCY_TARGET,
        "rescue",    SPECIAL_RESCUE_TARGET,
        "single",    SPECIAL_RESCUE_TARGET,
        "-s",        SPECIAL_RESCUE_TARGET,
        "s",         SPECIAL_RESCUE_TARGET,
        "S",         SPECIAL_RESCUE_TARGET,
        "1",         SPECIAL_RESCUE_TARGET,
        "2",         SPECIAL_MULTI_USER_TARGET,
        "3",         SPECIAL_MULTI_USER_TARGET,
        "4",         SPECIAL_MULTI_USER_TARGET,
        "5",         SPECIAL_GRAPHICAL_TARGET,
        NULL
};

static const char * const rlmap_initrd[] = {
        "emergency", SPECIAL_EMERGENCY_TARGET,
        "rescue",    SPECIAL_RESCUE_TARGET,
        NULL
};

const char* runlevel_to_target(const char *word) {
        const char * const *rlmap_ptr;
        size_t i;

        if (!word)
                return NULL;

        if (in_initrd()) {
                word = startswith(word, "rd.");
                if (!word)
                        return NULL;
        }

        rlmap_ptr = in_initrd() ? rlmap_initrd : rlmap;

        for (i = 0; rlmap_ptr[i]; i += 2)
                if (streq(word, rlmap_ptr[i]))
                        return rlmap_ptr[i+1];

        return NULL;
}
