/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>

#if HAVE_PWQUALITY
/* pwquality.h uses size_t but doesn't include sys/types.h on its own */
#include <sys/types.h>
#include <pwquality.h>
#endif

#include "bus-common-errors.h"
#include "home-util.h"
#include "memory-util.h"
#include "pwquality-util.h"
#include "strv.h"

#if HAVE_PWQUALITY
DEFINE_TRIVIAL_CLEANUP_FUNC(pwquality_settings_t*, pwquality_free_settings);

static void pwquality_maybe_disable_dictionary(
                pwquality_settings_t *pwq) {

        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        const char *path;
        int r;

        r = pwquality_get_str_value(pwq, PWQ_SETTING_DICT_PATH, &path);
        if (r < 0) {
                log_warning("Failed to read libpwquality dictionary path, ignoring: %s", pwquality_strerror(buf, sizeof(buf), r, NULL));
                return;
        }

        // REMOVE THIS AS SOON AS https://github.com/libpwquality/libpwquality/pull/21 IS MERGED AND RELEASED
        if (isempty(path))
                path = "/usr/share/cracklib/pw_dict.pwd.gz";

        if (isempty(path)) {
                log_warning("Weird, no dictionary file configured, ignoring.");
                return;
        }

        if (access(path, F_OK) >= 0)
                return;

        if (errno != ENOENT) {
                log_warning_errno(errno, "Failed to check if dictionary file %s exists, ignoring: %m", path);
                return;
        }

        r = pwquality_set_int_value(pwq, PWQ_SETTING_DICT_CHECK, 0);
        if (r < 0) {
                log_warning("Failed to disable libpwquality dictionary check, ignoring: %s", pwquality_strerror(buf, sizeof(buf), r, NULL));
                return;
        }
}

int quality_check_password(
                UserRecord *hr,
                UserRecord *secret,
                sd_bus_error *error) {

        _cleanup_(pwquality_free_settingsp) pwquality_settings_t *pwq = NULL;
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN], **pp;
        void *auxerror;
        int r;

        assert(hr);
        assert(secret);

        pwq = pwquality_default_settings();
        if (!pwq)
                return log_oom();

        r = pwquality_read_config(pwq, NULL, &auxerror);
        if (r < 0)
                log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to read libpwquality configuation, ignoring: %s",
                                  pwquality_strerror(buf, sizeof(buf), r, auxerror));

        pwquality_maybe_disable_dictionary(pwq);

        /* This is a bit more complex than one might think at first. pwquality_check() would like to know the
         * old password to make security checks. We support arbitrary numbers of passwords however, hence we
         * call the function once for each combination of old and new password. */

        /* Iterate through all new passwords */
        STRV_FOREACH(pp, secret->password) {
                bool called = false;
                char **old;

                r = test_password_many(hr->hashed_password, *pp);
                if (r < 0)
                        return r;
                if (r == 0) /* This is an old password as it isn't listed in the hashedPassword field, skip it */
                        continue;

                /* Check this password against all old passwords */
                STRV_FOREACH(old, secret->password) {

                        if (streq(*pp, *old))
                                continue;

                        r = test_password_many(hr->hashed_password, *old);
                        if (r < 0)
                                return r;
                        if (r > 0) /* This is a new password, not suitable as old password */
                                continue;

                        r = pwquality_check(pwq, *pp, *old, hr->user_name, &auxerror);
                        if (r < 0)
                                return sd_bus_error_setf(error, BUS_ERROR_LOW_PASSWORD_QUALITY, "Password too weak: %s",
                                                         pwquality_strerror(buf, sizeof(buf), r, auxerror));

                        called = true;
                }

                if (called)
                        continue;

                /* If there are no old passwords, let's call pwquality_check() without any. */
                r = pwquality_check(pwq, *pp, NULL, hr->user_name, &auxerror);
                if (r < 0)
                        return sd_bus_error_setf(error, BUS_ERROR_LOW_PASSWORD_QUALITY, "Password too weak: %s",
                                                 pwquality_strerror(buf, sizeof(buf), r, auxerror));
        }

        return 0;
}

#define N_SUGGESTIONS 6

int suggest_passwords(void) {
        _cleanup_(pwquality_free_settingsp) pwquality_settings_t *pwq = NULL;
        _cleanup_strv_free_erase_ char **suggestions = NULL;
        _cleanup_(erase_and_freep) char *joined = NULL;
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        void *auxerror;
        size_t i;
        int r;

        pwq = pwquality_default_settings();
        if (!pwq)
                return log_oom();

        r = pwquality_read_config(pwq, NULL, &auxerror);
        if (r < 0)
                log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to read libpwquality configuation, ignoring: %s",
                                  pwquality_strerror(buf, sizeof(buf), r, auxerror));

        pwquality_maybe_disable_dictionary(pwq);

        suggestions = new0(char*, N_SUGGESTIONS);
        if (!suggestions)
                return log_oom();

        for (i = 0; i < N_SUGGESTIONS; i++) {
                r = pwquality_generate(pwq, 64, suggestions + i);
                if (r < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to generate password, ignoring: %s",
                                               pwquality_strerror(buf, sizeof(buf), r, NULL));
        }

        joined = strv_join(suggestions, " ");
        if (!joined)
                return log_oom();

        log_info("Password suggestions: %s", joined);
        return 0;
}

#else

int quality_check_password(
                UserRecord *hr,
                UserRecord *secret,
                sd_bus_error *error) {

        assert(hr);
        assert(secret);

        return 0;
}

int suggest_passwords(void) {
        return 0;
}
#endif
