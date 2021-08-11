/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dlfcn-util.h"
#include "errno-util.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "password-quality-util.h"
#include "strv.h"

#if HAVE_PASSWDQC

static void *passwdqc_dl = NULL;

void (*sym_passwdqc_params_reset)(passwdqc_params_t *params);
int (*sym_passwdqc_params_load)(passwdqc_params_t *params, char **reason, const char *pathname);
int (*sym_passwdqc_params_parse)(passwdqc_params_t *params, char **reason, int argc, const char *const *argv);
void (*sym_passwdqc_params_free)(passwdqc_params_t *params);
const char *(*sym_passwdqc_check)(const passwdqc_params_t *params, const char *newpass, const char *oldpass, const struct passwd *pw);
char *(*sym_passwdqc_random)(const passwdqc_params_t *params);

int dlopen_passwdqc(void) {
        return dlopen_many_sym_or_warn(
                        &passwdqc_dl, "libpasswdqc.so.1", LOG_DEBUG,
                        DLSYM_ARG(passwdqc_params_reset),
                        DLSYM_ARG(passwdqc_params_load),
                        DLSYM_ARG(passwdqc_params_parse),
                        DLSYM_ARG(passwdqc_params_free),
                        DLSYM_ARG(passwdqc_check),
                        DLSYM_ARG(passwdqc_random));
}

#define PASSWDQC_CONFIG "/etc/passwdqc.conf"

static int pwqc_allocate_context(passwdqc_params_t **ret) {
        _cleanup_(sym_passwdqc_params_freep) passwdqc_params_t *params = NULL;
        _cleanup_free_ char *load_reason;
        int r;

        assert(ret);

        r = dlopen_passwdqc();
        if (r < 0)
                return r;

        params = new0(passwdqc_params_t, 1);
        if (!params)
                return -ENOMEM;

        sym_passwdqc_params_reset(params);

        r = sym_passwdqc_params_load(params, &load_reason, PASSWDQC_CONFIG);
        if (r < 0) {
                log_debug("Failed to load passwdqc configuration '%s', ignoring: %s",
                          PASSWDQC_CONFIG, load_reason);
        }

        *ret = TAKE_PTR(params);
        return 0;
}

#define N_SUGGESTIONS 6

int suggest_passwords(void) {
        _cleanup_(sym_passwdqc_params_freep) passwdqc_params_t *params = NULL;
        _cleanup_strv_free_erase_ char **suggestions = NULL;
        _cleanup_(erase_and_freep) char *joined = NULL;
        size_t i;
        int r;

        r = pwqc_allocate_context(&params);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libpasswdqc context: %m");

        suggestions = new0(char*, N_SUGGESTIONS+1);
        if (!suggestions)
                return log_oom();

        for (i = 0; i < N_SUGGESTIONS; i++) {
                suggestions[i] = sym_passwdqc_random(params);
                if (!suggestions[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate password, ignoring");
        }

        joined = strv_join(suggestions, " ");
        if (!joined)
                return log_oom();

        log_info("Password suggestions: %s", joined);
        return 1;
}

int check_password_quality(
                const char *password,
                const char *old,
                const char *username,
                char **ret_error) {
        _cleanup_(sym_passwdqc_params_freep) passwdqc_params_t *params = NULL;
        const char *check_reason;
        int r;

        assert(password);

        r = pwqc_allocate_context(&params);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to allocate libpasswdqc context: %m");

        if (username) {
                _cleanup_free_ char *name = NULL;
                _cleanup_free_ char *empty = NULL;
                name = strdup(username);
                empty = strdup("");
                if (!name || !empty)
                        return -ENOMEM;

                struct passwd pw = {
                        .pw_name = name,
                        .pw_gecos = empty,
                        .pw_dir = empty
                };
                check_reason = sym_passwdqc_check(params, password, old, &pw);
        } else
                check_reason = sym_passwdqc_check(params, password, old, NULL);

        if (check_reason != NULL) {
                if (ret_error){
                        _cleanup_free_ char *e = NULL;
                        e = strdup(check_reason);
                        if (!e)
                                return -ENOMEM;
                        *ret_error = TAKE_PTR(e);
                }

                return 0; /* all bad */
        }

        return 1; /* all good */
}

#endif
