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

DLSYM_PROTOTYPE(passwdqc_params_reset) = NULL;
DLSYM_PROTOTYPE(passwdqc_params_load) = NULL;
DLSYM_PROTOTYPE(passwdqc_params_parse) = NULL;
DLSYM_PROTOTYPE(passwdqc_params_free) = NULL;
DLSYM_PROTOTYPE(passwdqc_check) = NULL;
DLSYM_PROTOTYPE(passwdqc_random) = NULL;

int dlopen_passwdqc(void) {
        ELF_NOTE_DLOPEN("passwdqc",
                        "Support for password quality checks",
                        ELF_NOTE_DLOPEN_PRIORITY_SUGGESTED,
                        "libpasswdqc.so.1");

        return dlopen_many_sym_or_warn(
                        &passwdqc_dl, "libpasswdqc.so.1", LOG_DEBUG,
                        DLSYM_ARG(passwdqc_params_reset),
                        DLSYM_ARG(passwdqc_params_load),
                        DLSYM_ARG(passwdqc_params_parse),
                        DLSYM_ARG(passwdqc_params_free),
                        DLSYM_ARG(passwdqc_check),
                        DLSYM_ARG(passwdqc_random));
}

static int pwqc_allocate_context(passwdqc_params_t **ret) {

        _cleanup_(sym_passwdqc_params_freep) passwdqc_params_t *params = NULL;
        _cleanup_free_ char *load_reason = NULL;
        int r;

        assert(ret);

        r = dlopen_passwdqc();
        if (r < 0)
                return r;

        params = new0(passwdqc_params_t, 1);
        if (!params)
                return log_oom();

        sym_passwdqc_params_reset(params);

        r = sym_passwdqc_params_load(params, &load_reason, "/etc/passwdqc.conf");
        if (r < 0) {
                if (!load_reason)
                        return log_oom();
                log_debug("Failed to load passwdqc configuration file, ignoring: %s", load_reason);
        }

        *ret = TAKE_PTR(params);
        return 0;
}

int suggest_passwords(void) {

        _cleanup_(sym_passwdqc_params_freep) passwdqc_params_t *params = NULL;
        _cleanup_strv_free_erase_ char **suggestions = NULL;
        _cleanup_(erase_and_freep) char *joined = NULL;
        int r;

        r = pwqc_allocate_context(&params);
        if (r < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(r))
                        return 0;
                return log_error_errno(r, "Failed to allocate libpasswdqc context: %m");
        }

        suggestions = new0(char*, N_SUGGESTIONS+1);
        if (!suggestions)
                return log_oom();

        for (size_t i = 0; i < N_SUGGESTIONS; i++) {
                suggestions[i] = sym_passwdqc_random(&params->qc);
                if (!suggestions[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate password, ignoring");
        }

        joined = strv_join(suggestions, " ");
        if (!joined)
                return log_oom();

        printf("Password suggestions: %s\n", joined);
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
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate libpasswdqc context: %m");

        if (username) {
                const struct passwd pw = {
                        .pw_name = (char *) username,
                        /*
                         * passwdqc_check() could use this information to check
                         * whether the password is based on the personal login information,
                         * but we cannot provide it.
                         */
                        .pw_passwd = (char *) "",
                        .pw_gecos = (char *) "",
                        .pw_dir = (char *) "",
                        .pw_shell = (char *) ""
                };

                check_reason = sym_passwdqc_check(&params->qc, password, old, &pw);
        } else
                check_reason = sym_passwdqc_check(&params->qc, password, old, /* pw */ NULL);

        if (check_reason) {
                if (ret_error) {
                        char *e = strdup(check_reason);
                        if (!e)
                                return log_oom();
                        *ret_error = e;
                }

                return 0; /* all bad */
        }

        return 1; /* all good */
}

#endif
