/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>

#include "env-file-label.h"
#include "env-file.h"
#include "env-util.h"
#include "locale-setup.h"
#include "proc-cmdline.h"
#include "strv.h"

void locale_context_clear(LocaleContext *c) {
        assert(c);

        c->mtime = USEC_INFINITY;

        for (LocaleVariable i = 0; i < _VARIABLE_LC_MAX; i++)
                c->locale[i] = mfree(c->locale[i]);
}

int locale_context_load(LocaleContext *c, LocaleLoadFlag flag) {
        int r;

        assert(c);

        if (FLAGS_SET(flag, LOCALE_LOAD_PROC_CMDLINE)) {
                locale_context_clear(c);

                r = proc_cmdline_get_key_many(PROC_CMDLINE_STRIP_RD_PREFIX,
                                              "locale.LANG",              &c->locale[VARIABLE_LANG],
                                              "locale.LANGUAGE",          &c->locale[VARIABLE_LANGUAGE],
                                              "locale.LC_CTYPE",          &c->locale[VARIABLE_LC_CTYPE],
                                              "locale.LC_NUMERIC",        &c->locale[VARIABLE_LC_NUMERIC],
                                              "locale.LC_TIME",           &c->locale[VARIABLE_LC_TIME],
                                              "locale.LC_COLLATE",        &c->locale[VARIABLE_LC_COLLATE],
                                              "locale.LC_MONETARY",       &c->locale[VARIABLE_LC_MONETARY],
                                              "locale.LC_MESSAGES",       &c->locale[VARIABLE_LC_MESSAGES],
                                              "locale.LC_PAPER",          &c->locale[VARIABLE_LC_PAPER],
                                              "locale.LC_NAME",           &c->locale[VARIABLE_LC_NAME],
                                              "locale.LC_ADDRESS",        &c->locale[VARIABLE_LC_ADDRESS],
                                              "locale.LC_TELEPHONE",      &c->locale[VARIABLE_LC_TELEPHONE],
                                              "locale.LC_MEASUREMENT",    &c->locale[VARIABLE_LC_MEASUREMENT],
                                              "locale.LC_IDENTIFICATION", &c->locale[VARIABLE_LC_IDENTIFICATION]);
                if (r < 0 && r != -ENOENT)
                        log_debug_errno(r, "Failed to read /proc/cmdline, ignoring: %m");
                if (r > 0)
                        goto finalize;
        }

        if (FLAGS_SET(flag, LOCALE_LOAD_LOCALE_CONF)) {
                struct stat st;
                usec_t t;

                r = stat("/etc/locale.conf", &st);
                if (r < 0 && errno != ENOENT)
                        return log_debug_errno(errno, "Failed to stat /etc/locale.conf: %m");

                if (r >= 0) {
                        /* If mtime is not changed, then we do not need to re-read the file. */
                        t = timespec_load(&st.st_mtim);
                        if (c->mtime != USEC_INFINITY && t == c->mtime)
                                return 0;

                        locale_context_clear(c);
                        c->mtime = t;

                        r = parse_env_file(NULL, "/etc/locale.conf",
                                           "LANG",              &c->locale[VARIABLE_LANG],
                                           "LANGUAGE",          &c->locale[VARIABLE_LANGUAGE],
                                           "LC_CTYPE",          &c->locale[VARIABLE_LC_CTYPE],
                                           "LC_NUMERIC",        &c->locale[VARIABLE_LC_NUMERIC],
                                           "LC_TIME",           &c->locale[VARIABLE_LC_TIME],
                                           "LC_COLLATE",        &c->locale[VARIABLE_LC_COLLATE],
                                           "LC_MONETARY",       &c->locale[VARIABLE_LC_MONETARY],
                                           "LC_MESSAGES",       &c->locale[VARIABLE_LC_MESSAGES],
                                           "LC_PAPER",          &c->locale[VARIABLE_LC_PAPER],
                                           "LC_NAME",           &c->locale[VARIABLE_LC_NAME],
                                           "LC_ADDRESS",        &c->locale[VARIABLE_LC_ADDRESS],
                                           "LC_TELEPHONE",      &c->locale[VARIABLE_LC_TELEPHONE],
                                           "LC_MEASUREMENT",    &c->locale[VARIABLE_LC_MEASUREMENT],
                                           "LC_IDENTIFICATION", &c->locale[VARIABLE_LC_IDENTIFICATION]);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to read /etc/locale.conf: %m");

                        goto finalize;
                }
        }

        if (FLAGS_SET(flag, LOCALE_LOAD_ENVIRONMENT)) {
                locale_context_clear(c);

                /* Fill in what we got passed from systemd. */
                for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++) {
                        const char *name = ASSERT_PTR(locale_variable_to_string(p));

                        r = free_and_strdup(&c->locale[p], empty_to_null(getenv(name)));
                        if (r < 0)
                                return log_oom_debug();
                }

                goto finalize;
        }

        /* Nothing loaded. */
        locale_context_clear(c);
        return 0;

finalize:
        if (FLAGS_SET(flag, LOCALE_LOAD_SIMPLIFY))
                locale_variables_simplify(c->locale);

        return 0;
}

int locale_context_build_env(const LocaleContext *c, char ***ret_set, char ***ret_unset) {
        _cleanup_strv_free_ char **set = NULL, **unset = NULL;
        int r;

        assert(c);

        if (!ret_set && !ret_unset)
                return 0;

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++) {
                const char *name = ASSERT_PTR(locale_variable_to_string(p));

                if (isempty(c->locale[p])) {
                        if (!ret_unset)
                                continue;
                        r = strv_extend(&unset, name);
                } else {
                        if (!ret_set)
                                continue;
                        r = strv_env_assign(&set, name, c->locale[p]);
                }
                if (r < 0)
                        return r;
        }

        if (ret_set)
                *ret_set = TAKE_PTR(set);
        if (ret_unset)
                *ret_unset = TAKE_PTR(unset);
        return 0;
}

int locale_context_save(LocaleContext *c, char ***ret_set, char ***ret_unset) {
        _cleanup_strv_free_ char **set = NULL, **unset = NULL;
        struct stat st;
        int r;

        assert(c);

        /* Set values will be returned as strv in *ret on success. */

        r = locale_context_build_env(c, &set, ret_unset ? &unset : NULL);
        if (r < 0)
                return r;

        if (strv_isempty(set)) {
                if (unlink("/etc/locale.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                c->mtime = USEC_INFINITY;
                if (ret_set)
                        *ret_set = NULL;
                if (ret_unset)
                        *ret_unset = NULL;
                return 0;
        }

        r = write_env_file_label("/etc/locale.conf", set);
        if (r < 0)
                return r;

        if (stat("/etc/locale.conf", &st) >= 0)
                c->mtime = timespec_load(&st.st_mtim);

        if (ret_set)
                *ret_set = TAKE_PTR(set);
        if (ret_unset)
                *ret_unset = TAKE_PTR(unset);
        return 0;
}

int locale_context_merge(const LocaleContext *c, char *l[_VARIABLE_LC_MAX]) {
        assert(c);
        assert(l);

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++)
                if (!isempty(c->locale[p]) && isempty(l[p])) {
                        l[p] = strdup(c->locale[p]);
                        if (!l[p])
                                return -ENOMEM;
                }

        return 0;
}

void locale_context_take(LocaleContext *c, char *l[_VARIABLE_LC_MAX]) {
        assert(c);
        assert(l);

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++)
                free_and_replace(c->locale[p], l[p]);
}

bool locale_context_equal(const LocaleContext *c, char *l[_VARIABLE_LC_MAX]) {
        assert(c);
        assert(l);

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++)
                if (!streq_ptr(c->locale[p], l[p]))
                        return false;

        return true;
}

int locale_setup(char ***environment) {
        _cleanup_(locale_context_clear) LocaleContext c = { .mtime = USEC_INFINITY };
        _cleanup_strv_free_ char **add = NULL;
        int r;

        assert(environment);

        r = locale_context_load(&c, LOCALE_LOAD_PROC_CMDLINE | LOCALE_LOAD_LOCALE_CONF);
        if (r < 0)
                return r;

        r = locale_context_build_env(&c, &add, NULL);
        if (r < 0)
                return r;

        if (strv_isempty(add)) {
                /* If no locale is configured then default to compile-time default. */

                add = strv_new("LANG=" SYSTEMD_DEFAULT_LOCALE);
                if (!add)
                        return -ENOMEM;
        }

        if (strv_isempty(*environment))
                strv_free_and_replace(*environment, add);
        else {
                char **merged;

                merged = strv_env_merge(*environment, add);
                if (!merged)
                        return -ENOMEM;

                strv_free_and_replace(*environment, merged);
        }

        return 0;
}
