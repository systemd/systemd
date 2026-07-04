/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "efivars.h"
#include "env-file.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "locale-setup.h"
#include "log.h"
#include "proc-cmdline.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

void locale_context_clear(LocaleContext *c) {
        assert(c);

        c->st = (struct stat) {};

        for (LocaleVariable i = 0; i < _VARIABLE_LC_MAX; i++)
                c->locale[i] = mfree(c->locale[i]);
}

static int locale_context_load_proc(LocaleContext *c, LocaleLoadFlag flag) {
        int r;

        assert(c);

        if (!FLAGS_SET(flag, LOCALE_LOAD_PROC_CMDLINE))
                return 0;

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
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to read /proc/cmdline: %m");
        return r;
}

static int locale_context_load_conf(LocaleContext *c, LocaleLoadFlag flag) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        assert(c);

        if (!FLAGS_SET(flag, LOCALE_LOAD_LOCALE_CONF))
                return 0;

        fd = RET_NERRNO(open(etc_locale_conf(), O_CLOEXEC | O_PATH));
        if (fd == -ENOENT)
                return 0;
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open %s: %m", "/etc/locale.conf");

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat /etc/locale.conf: %m");

        /* If the file is not changed, then we do not need to re-read the file. */
        if (stat_inode_unmodified(&c->st, &st))
                return 1; /* (already) loaded */

        c->st = st;
        locale_context_clear(c);

        r = parse_env_file_fd(fd, etc_locale_conf(),
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

        return 1; /* loaded */
}

static int locale_context_load_env(LocaleContext *c, LocaleLoadFlag flag) {
        int r;

        assert(c);

        if (!FLAGS_SET(flag, LOCALE_LOAD_ENVIRONMENT))
                return 0;

        locale_context_clear(c);

        /* Fill in what we got passed from systemd. */
        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++) {
                const char *name = ASSERT_PTR(locale_variable_to_string(p));

                r = free_and_strdup(&c->locale[p], empty_to_null(getenv(name)));
                if (r < 0)
                        return log_oom_debug();
        }

        return 1; /* loaded */
}

int locale_context_load(LocaleContext *c, LocaleLoadFlag flag) {
        int r;

        assert(c);

        r = locale_context_load_proc(c, flag);
        if (r > 0)
                goto finalize;

        r = locale_context_load_conf(c, flag);
        if (r != 0)
                goto finalize;

        r = locale_context_load_env(c, flag);

finalize:
        if (r <= 0) {
                /* Nothing loaded, or error. */
                locale_context_clear(c);
                return r;
        }

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
        int r;

        assert(c);

        /* Set values will be returned as strv in *ret on success. */

        r = locale_context_build_env(c, &set, ret_unset ? &unset : NULL);
        if (r < 0)
                return r;

        if (strv_isempty(set)) {
                if (unlink(etc_locale_conf()) < 0)
                        return errno == ENOENT ? 0 : -errno;

                c->st = (struct stat) {};

                if (ret_set)
                        *ret_set = NULL;
                if (ret_unset)
                        *ret_unset = NULL;
                return 0;
        }

        r = write_env_file(
                        AT_FDCWD,
                        etc_locale_conf(),
                        /* headers= */ NULL,
                        set,
                        WRITE_ENV_FILE_LABEL,
                        NULL);
        if (r < 0)
                return r;

        if (stat(etc_locale_conf(), &c->st) < 0)
                return -errno;

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
        _cleanup_(locale_context_clear) LocaleContext c = {};
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

const char* etc_locale_conf(void) {
        static const char *cached = NULL;

        if (!cached)
                cached = secure_getenv("SYSTEMD_ETC_LOCALE_CONF") ?: "/etc/locale.conf";

        return cached;
}

const char* etc_vconsole_conf(void) {
        static const char *cached = NULL;

        if (!cached)
                cached = secure_getenv("SYSTEMD_ETC_VCONSOLE_CONF") ?: "/etc/vconsole.conf";

        return cached;
}

int locale_lang_from_efi(char **ret, LocaleLangFromEfiFlags flags) {
        int r;

        assert(ret);

        if (!is_efi_boot()) {
                *ret = NULL;
                return 0;
        }

        /* NB: unlike most other UEFI variables, PlatformLang is actually in 7bit ASCII! Hence we are not
         * using efi_get_variable_string() here */
        _cleanup_(iovec_done) struct iovec iov = {};
        r = efi_get_variable(EFI_GLOBAL_VARIABLE_STR("PlatformLang"), /* ret_attribute= */ NULL, &iov.iov_base, &iov.iov_len);
        if (r == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to read PlatformLang EFI variable: %m");

        _cleanup_free_ char *tag = NULL;
        r = make_cstring(iov.iov_base, iov.iov_len, MAKE_CSTRING_ALLOW_TRAILING_NUL, &tag);
        if (r < 0)
                return log_debug_errno(r, "Failed to convert PlatformLang EFI variable to C string: %m");

        /* Convert the UEFI BCP47 language tag into a glibc tag. We'll not bother with the complexity of the
         * whole spec, but just convert "xx-XX" into "xx_XX", with some flexibility on the case
         * sensitivity. This is a best-effort thing anyway. */

        if (strlen(tag) != 5 ||
            !strchr(LETTERS, tag[0]) ||
            !strchr(LETTERS, tag[1]) ||
            tag[2] != '-' ||
            !strchr(LETTERS, tag[3]) ||
            !strchr(LETTERS, tag[4])) {
                log_debug("PlatformLang variable does not have the form 'xx-XX', ignoring: %s", tag);
                *ret = NULL;
                return 0;
        }

        tag[0] = ascii_tolower(tag[0]);
        tag[1] = ascii_tolower(tag[1]);
        tag[2] = '_';
        tag[3] = ascii_toupper(tag[3]);
        tag[4] = ascii_toupper(tag[4]);

        /* Let's optionally suppress en_US locale, since that's almost certainly just the built-in default
         * locale of the firmware. Since we typically prefer C.UTF-8 over en_US.UTF-8 as default, let's hence
         * suppress it. */
        if (FLAGS_SET(flags, LOCALE_SUPPRESS_EN_US) && streq(tag, "en_US")) {
                log_debug("Firmware language is en_US, suppressing because likely just the firmware default.");
                *ret = NULL;
                return 0;
        }

        if (!strextend(&tag, ".UTF-8"))
                return -ENOMEM;

        if (FLAGS_SET(flags, LOCALE_REQUIRE_INSTALLED)) {
                r = locale_is_installed(tag);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_debug("Determined locale '%s' from PlatformLang, but it isn't installed, ignoring.", tag);
                        *ret = NULL;
                        return 0;
                }
        }

        *ret = TAKE_PTR(tag);
        return 1;
}
