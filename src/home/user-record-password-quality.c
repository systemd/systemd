/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-common-errors.h"
#include "errno-util.h"
#include "libcrypt-util.h"
#include "log.h"
#include "password-quality-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-record.h"
#include "user-record-password-quality.h"

#if HAVE_PASSWDQC || HAVE_PWQUALITY

int user_record_check_password_quality(
                UserRecord *hr,
                UserRecord *secret,
                sd_bus_error *error) {

        _cleanup_free_ char *auxerror = NULL;
        int r;

        assert(hr);
        assert(secret);

        /* This is a bit more complex than one might think at first. check_password_quality() would like to know the
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

                        r = check_password_quality(*pp, *old, hr->user_name, &auxerror);
                        if (r <= 0)
                                goto error;

                        called = true;
                }

                if (called)
                        continue;

                /* If there are no old passwords, let's call check_password_quality() without any. */
                r = check_password_quality(*pp, /* old = */ NULL, hr->user_name, &auxerror);
                if (r <= 0)
                        goto error;
        }
        return 1;

error:
        if (r == 0)
                return sd_bus_error_setf(error, BUS_ERROR_LOW_PASSWORD_QUALITY,
                                         "Password too weak: %s", auxerror);
        if (ERRNO_IS_NOT_SUPPORTED(r))
                return 0;
        return log_debug_errno(r, "Failed to check password quality: %m");
}

#else

int user_record_check_password_quality(
                UserRecord *hr,
                UserRecord *secret,
                sd_bus_error *error) {

        return 0;
}

#endif
