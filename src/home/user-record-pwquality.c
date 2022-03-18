/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-common-errors.h"
#include "errno-util.h"
#include "home-util.h"
#include "libcrypt-util.h"
#include "pwquality-util.h"
#include "strv.h"
#include "user-record-pwquality.h"
#include "user-record-util.h"

#if HAVE_PWQUALITY

int user_record_quality_check_password(
                UserRecord *hr,
                UserRecord *secret,
                sd_bus_error *error) {

        _cleanup_(sym_pwquality_free_settingsp) pwquality_settings_t *pwq = NULL;
        char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
        void *auxerror;
        int r;

        assert(hr);
        assert(secret);

        r = pwq_allocate_context(&pwq);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate libpwquality context: %m");

        /* This is a bit more complex than one might think at first. pwquality_check() would like to know the
         * old password to make security checks. We support arbitrary numbers of passwords however, hence we
         * call the function once for each combination of old and new password. */

        /* Iterate through all new passwords */
        STRV_FOREACH(pp, secret->password) {
                bool called = false;

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

                        r = sym_pwquality_check(pwq, *pp, *old, hr->user_name, &auxerror);
                        if (r < 0)
                                return sd_bus_error_setf(error, BUS_ERROR_LOW_PASSWORD_QUALITY, "Password too weak: %s",
                                                         sym_pwquality_strerror(buf, sizeof(buf), r, auxerror));

                        called = true;
                }

                if (called)
                        continue;

                /* If there are no old passwords, let's call pwquality_check() without any. */
                r = sym_pwquality_check(pwq, *pp, NULL, hr->user_name, &auxerror);
                if (r < 0)
                        return sd_bus_error_setf(error, BUS_ERROR_LOW_PASSWORD_QUALITY, "Password too weak: %s",
                                                 sym_pwquality_strerror(buf, sizeof(buf), r, auxerror));
        }

        return 1;
}

#else

int user_record_quality_check_password(
                UserRecord *hr,
                UserRecord *secret,
                sd_bus_error *error) {

        return 0;
}

#endif
