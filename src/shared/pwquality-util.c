/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "dlfcn-util.h"
#include "errno-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "pwquality-util.h"
#include "strv.h"

#if HAVE_PWQUALITY

static void *pwquality_dl = NULL;

int (*sym_pwquality_check)(pwquality_settings_t *pwq, const char *password, const char *oldpassword, const char *user, void **auxerror);
pwquality_settings_t *(*sym_pwquality_default_settings)(void);
void (*sym_pwquality_free_settings)(pwquality_settings_t *pwq);
int (*sym_pwquality_generate)(pwquality_settings_t *pwq, int entropy_bits, char **password);
int (*sym_pwquality_get_str_value)(pwquality_settings_t *pwq, int setting, const char **value);
int (*sym_pwquality_read_config)(pwquality_settings_t *pwq, const char *cfgfile, void **auxerror);
int (*sym_pwquality_set_int_value)(pwquality_settings_t *pwq, int setting, int value);
const char* (*sym_pwquality_strerror)(char *buf, size_t len, int errcode, void *auxerror);

int dlopen_pwquality(void) {
        _cleanup_(dlclosep) void *dl = NULL;
        int r;

        if (pwquality_dl)
                return 0; /* Already loaded */

        dl = dlopen("libpwquality.so.1", RTLD_LAZY);
        if (!dl)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "libpwquality support is not installed: %s", dlerror());

        r = dlsym_many_and_warn(
                        dl,
                        LOG_DEBUG,
                        DLSYM_ARG(pwquality_check),
                        DLSYM_ARG(pwquality_default_settings),
                        DLSYM_ARG(pwquality_free_settings),
                        DLSYM_ARG(pwquality_generate),
                        DLSYM_ARG(pwquality_get_str_value),
                        DLSYM_ARG(pwquality_read_config),
                        DLSYM_ARG(pwquality_set_int_value),
                        DLSYM_ARG(pwquality_strerror),
                        NULL);
        if (r < 0)
                return r;

        /* Note that we never release the reference here, because there's no real reason to, after all this
         * was traditionally a regular shared library dependency which lives forever too. */
        pwquality_dl = TAKE_PTR(dl);
        return 1;
}

void pwq_maybe_disable_dictionary(pwquality_settings_t *pwq) {
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        const char *path;
        int r;

        assert(pwq);

        r = sym_pwquality_get_str_value(pwq, PWQ_SETTING_DICT_PATH, &path);
        if (r < 0) {
                log_debug("Failed to read libpwquality dictionary path, ignoring: %s",
                          sym_pwquality_strerror(buf, sizeof(buf), r, NULL));
                return;
        }

        // REMOVE THIS AS SOON AS https://github.com/libpwquality/libpwquality/pull/21 IS MERGED AND RELEASED
        if (isempty(path))
                path = "/usr/share/cracklib/pw_dict.pwd.gz";

        if (isempty(path)) {
                log_debug("Weird, no dictionary file configured, ignoring.");
                return;
        }

        if (access(path, F_OK) >= 0)
                return;

        if (errno != ENOENT) {
                log_debug_errno(errno, "Failed to check if dictionary file %s exists, ignoring: %m", path);
                return;
        }

        r = sym_pwquality_set_int_value(pwq, PWQ_SETTING_DICT_CHECK, 0);
        if (r < 0)
                log_debug("Failed to disable libpwquality dictionary check, ignoring: %s",
                          sym_pwquality_strerror(buf, sizeof(buf), r, NULL));
}

int pwq_allocate_context(pwquality_settings_t **ret) {
        _cleanup_(sym_pwquality_free_settingsp) pwquality_settings_t *pwq = NULL;
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        void *auxerror;
        int r;

        assert(ret);

        r = dlopen_pwquality();
        if (r < 0)
                return r;

        pwq = sym_pwquality_default_settings();
        if (!pwq)
                return -ENOMEM;

        r = sym_pwquality_read_config(pwq, NULL, &auxerror);
        if (r < 0)
                log_debug("Failed to read libpwquality configuration, ignoring: %s",
                          sym_pwquality_strerror(buf, sizeof(buf), r, auxerror));

        pwq_maybe_disable_dictionary(pwq);

        *ret = TAKE_PTR(pwq);
        return 0;
}

#define N_SUGGESTIONS 6

int suggest_passwords(void) {
        _cleanup_(sym_pwquality_free_settingsp) pwquality_settings_t *pwq = NULL;
        _cleanup_strv_free_erase_ char **suggestions = NULL;
        _cleanup_(erase_and_freep) char *joined = NULL;
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        size_t i;
        int r;

        r = pwq_allocate_context(&pwq);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libpwquality context: %m");

        suggestions = new0(char*, N_SUGGESTIONS+1);
        if (!suggestions)
                return log_oom();

        for (i = 0; i < N_SUGGESTIONS; i++) {
                r = sym_pwquality_generate(pwq, 64, suggestions + i);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate password, ignoring: %s",
                                               sym_pwquality_strerror(buf, sizeof(buf), r, NULL));
        }

        joined = strv_join(suggestions, " ");
        if (!joined)
                return log_oom();

        log_info("Password suggestions: %s", joined);
        return 1;
}

int quality_check_password(const char *password, const char *username, char **ret_error) {
        _cleanup_(sym_pwquality_free_settingsp) pwquality_settings_t *pwq = NULL;
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        void *auxerror;
        int r;

        assert(password);

        r = pwq_allocate_context(&pwq);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate libpwquality context: %m");

        r = sym_pwquality_check(pwq, password, NULL, username, &auxerror);
        if (r < 0) {

                if (ret_error) {
                        _cleanup_free_ char *e = NULL;

                        e = strdup(sym_pwquality_strerror(buf, sizeof(buf), r, auxerror));
                        if (!e)
                                return -ENOMEM;

                        *ret_error = TAKE_PTR(e);
                }

                return 0; /* all bad */
        }

        return 1; /* all good */
}

#endif
