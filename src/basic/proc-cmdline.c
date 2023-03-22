/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stddef.h>

#include "alloc-util.h"
#include "efivars.h"
#include "extract-word.h"
#include "fileio.h"
#include "initrd-util.h"
#include "macro.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "special.h"
#include "string-util.h"
#include "strv.h"
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

int proc_cmdline_strv(char ***ret) {
        const char *e;
        int r;

        assert(ret);

        /* For testing purposes it is sometimes useful to be able to override what we consider /proc/cmdline to be */
        e = secure_getenv("SYSTEMD_PROC_CMDLINE");
        if (e)
                return strv_split_full(ret, e, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);

        if (detect_container() > 0)
                return get_process_cmdline_strv(1, /* flags = */ 0, ret);
        else {
                _cleanup_free_ char *s = NULL;

                r = read_one_line_file("/proc/cmdline", &s);
                if (r < 0)
                        return r;

                return strv_split_full(ret, s, NULL, EXTRACT_UNQUOTE|EXTRACT_RELAX|EXTRACT_RETAIN_ESCAPE);
        }
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

        /* The PROC_CMDLINE_VALUE_OPTIONAL flag doesn't really make sense for proc_cmdline_parse(), let's
         * make this clear. */
        assert(!FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL));

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

        r = proc_cmdline_strv(&args);
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
                char *word;

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

        if (isempty(key))
                return -EINVAL;

        if (FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL) && !ret_value)
                return -EINVAL;

        r = proc_cmdline_strv(&args);
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

typedef struct ProcCmdlineDataEntry {
        const char *key;
        char *value;
        char **ret;
} ProcCmdlineDataEntry;

typedef struct ProcCmdlineData {
        ProcCmdlineDataEntry *data;
        size_t num;
} ProcCmdlineData;

static void proc_cmdline_data_done(ProcCmdlineData *c) {
        assert(c);

        FOREACH_ARRAY(e, c->data, c->num)
                free(e->value);

        free(c->data);
}

static int get_many_handler(const char *key, const char *value, void *data) {
        ProcCmdlineData *c = ASSERT_PTR(data);
        int r;

        assert(key);

        FOREACH_ARRAY(e, c->data, c->num) {
                if (!proc_cmdline_key_streq(e->key, key))
                        continue;

                if (value) {
                        r = free_and_strdup(&e->value, value);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int proc_cmdline_get_key_many_internal(ProcCmdlineFlags flags, ...) {
        _cleanup_(proc_cmdline_data_done) ProcCmdlineData c = {};
        va_list ap;
        int r;

        /* The PROC_CMDLINE_VALUE_OPTIONAL flag doesn't really make sense for proc_cmdline_get_key_many(),
         * let's make this clear. */
        assert(!FLAGS_SET(flags, PROC_CMDLINE_VALUE_OPTIONAL));

        va_start(ap, flags);
        for (;;) {
                const char *k;
                char **v;

                k = va_arg(ap, const char*);
                if (!k)
                        break;

                assert_se(v = va_arg(ap, char**));

                if (!GREEDY_REALLOC(c.data, c.num + 1)) {
                        va_end(ap);
                        return -ENOMEM;
                }

                c.data[c.num++] = (ProcCmdlineDataEntry) {
                        .key = k,
                        .ret = v,
                };
        }

        va_end(ap);

        if (c.num == 0)
                return 0; /* shortcut. */

        r = proc_cmdline_parse(get_many_handler, &c, flags);
        if (r < 0)
                return r;

        r = 0;
        FOREACH_ARRAY(e, c.data, c.num) {
                r += !!e->value;
                *e->ret = TAKE_PTR(e->value);
        }

        return r;
}
