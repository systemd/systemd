/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "dlfcn-util.h"
#include "errno-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "password-quality-util.h"
#include "strv.h"

#if HAVE_PWQUALITY

static void *pwquality_dl = NULL;

DLSYM_PROTOTYPE(pwquality_check) = NULL;
DLSYM_PROTOTYPE(pwquality_default_settings) = NULL;
DLSYM_PROTOTYPE(pwquality_free_settings) = NULL;
DLSYM_PROTOTYPE(pwquality_generate) = NULL;
DLSYM_PROTOTYPE(pwquality_get_str_value) = NULL;
DLSYM_PROTOTYPE(pwquality_read_config) = NULL;
DLSYM_PROTOTYPE(pwquality_set_int_value) = NULL;
DLSYM_PROTOTYPE(pwquality_strerror) = NULL;

int dlopen_pwquality(void) {
        ELF_NOTE_DLOPEN("pwquality",
                        "Support for password quality checks",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libpwquality.so.1");

        return dlopen_many_sym_or_warn(
                        &pwquality_dl, "libpwquality.so.1", LOG_DEBUG,
                        DLSYM_ARG(pwquality_check),
                        DLSYM_ARG(pwquality_default_settings),
                        DLSYM_ARG(pwquality_free_settings),
                        DLSYM_ARG(pwquality_generate),
                        DLSYM_ARG(pwquality_get_str_value),
                        DLSYM_ARG(pwquality_read_config),
                        DLSYM_ARG(pwquality_set_int_value),
                        DLSYM_ARG(pwquality_strerror));
}

static void pwq_maybe_disable_dictionary(pwquality_settings_t *pwq) {
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

static int pwq_allocate_context(pwquality_settings_t **ret) {
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

int suggest_passwords(void) {
        _cleanup_(sym_pwquality_free_settingsp) pwquality_settings_t *pwq = NULL;
        _cleanup_strv_free_erase_ char **suggestions = NULL;
        _cleanup_(erase_and_freep) char *joined = NULL;
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        int r;

        r = pwq_allocate_context(&pwq);
        if (r < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(r))
                        return 0;
                return log_error_errno(r, "Failed to allocate libpwquality context: %m");
        }

        suggestions = new0(char*, N_SUGGESTIONS+1);
        if (!suggestions)
                return log_oom();

        for (size_t i = 0; i < N_SUGGESTIONS; i++) {
                r = sym_pwquality_generate(pwq, 64, suggestions + i);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate password, ignoring: %s",
                                               sym_pwquality_strerror(buf, sizeof(buf), r, NULL));
        }

        joined = strv_join(suggestions, " ");
        if (!joined)
                return log_oom();

        printf("Password suggestions: %s\n", joined);
        return 1;
}

int check_password_quality(const char *password, const char *old, const char *username, char **ret_error) {
        _cleanup_(sym_pwquality_free_settingsp) pwquality_settings_t *pwq = NULL;
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        void *auxerror;
        int r;

        assert(password);

        r = pwq_allocate_context(&pwq);
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate libpwquality context: %m");

        r = sym_pwquality_check(pwq, password, old, username, &auxerror);
        if (r < 0) {
                if (ret_error) {
                        r = strdup_to(ret_error,
                                      sym_pwquality_strerror(buf, sizeof(buf), r, auxerror));
                        if (r < 0)
                                return r;
                }

                return 0; /* all bad */
        }

        return 1; /* all good */
}

#endif
