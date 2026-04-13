/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <time.h>

#include "iso9660.h"
#include "log.h"
#include "stdio-util.h"
#include "string-util.h"
#include "time-util.h"

void iso9660_datetime_zero(struct iso9660_datetime *ret) {
        assert(ret);

        memcpy(ret->year, "0000", 4);
        memcpy(ret->month, "00", 2);
        memcpy(ret->day, "00", 2);
        memcpy(ret->hour, "00", 2);
        memcpy(ret->minute, "00", 2);
        memcpy(ret->second, "00", 2);
        memcpy(ret->deci, "00", 2);
        ret->zone = 0;
}

static int validate_tm(const struct tm *t) {
        assert(t);

        /* Safety checks on bounded fields of struct tm, ranges as per tm(3type). Mostly in place because
         * ISO9660 date/time ranges and struct tm ranges differ. */

        if (t->tm_mon < 0 || t->tm_mon > 11)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Month out of range.");
        if (t->tm_mday < 1 || t->tm_mday > 31)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Day of month out of range.");
        if (t->tm_hour < 0 || t->tm_hour > 23)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Hour out of range.");
        if (t->tm_min < 0 || t->tm_min > 59)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Minute out of range.");
        if (t->tm_sec < 0 || t->tm_sec > 60)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Seconds out of range.");

        return 0;
}

int iso9660_datetime_from_usec(usec_t usec, bool utc, struct iso9660_datetime *ret) {
        struct tm t;
        int r;

        assert(ret);

        r = localtime_or_gmtime_usec(usec, utc, &t);
        if (r < 0)
                return r;

        r = validate_tm(&t);
        if (r < 0)
                return r;

        if (t.tm_year >= 10000 - 1900)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Year has more than 4 digits and is incompatible with ISO9660.");
        if (t.tm_year + 1900 < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Year is negative and is incompatible with ISO9660.");

        long offset = t.tm_gmtoff / (15*60); /* The time zone is encoded by 15 minutes increments */
        if (offset < INT8_MIN || offset > INT8_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "GMT offset out of range.");

        char buf[17];
        assert_cc(sizeof(buf)-1 == offsetof(struct iso9660_datetime, zone));
        /* Ignore leap seconds, no real hope for hardware. Deci-seconds always zero. */
        xsprintf(buf, "%04d%02d%02d%02d%02d%02d00",
                 t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                 t.tm_hour, t.tm_min, MIN(t.tm_sec, 59));
        memcpy(ret, buf, sizeof(buf)-1);

        ret->zone = offset;

        return 0;
}

int iso9660_dir_datetime_from_usec(usec_t usec, bool utc, struct iso9660_dir_time *ret) {
        struct tm t;
        int r;

        assert(ret);

        r = localtime_or_gmtime_usec(usec, utc, &t);
        if (r < 0)
                return r;

        r = validate_tm(&t);
        if (r < 0)
                return r;

        if (t.tm_year < 0 || t.tm_year > UINT8_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Year is incompatible with ISO9660.");

        long offset = t.tm_gmtoff / (15*60); /* The time zone is encoded by 15 minutes increments */
        if (offset < INT8_MIN || offset > INT8_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "GMT offset out of range.");

        *ret = (struct iso9660_dir_time) {
                .year = t.tm_year,
                .month = t.tm_mon + 1,
                .day = t.tm_mday,
                .hour = t.tm_hour,
                .minute = t.tm_min,
                .second = MIN(t.tm_sec, 59),
                /* The time zone is encoded by 15 minutes increments */
                .offset = offset,
        };

        return 0;
}

static bool iso9660_valid_string(const char *str, bool allow_a_chars) {
        /* note that a-chars are not supposed to accept lower case letters, but it looks like common practice
         * to use them
         */
        return in_charset(str, allow_a_chars ? UPPERCASE_LETTERS LOWERCASE_LETTERS DIGITS " _!\"%&'()*+,-./:;<=>?" : UPPERCASE_LETTERS DIGITS "_");
}

int iso9660_set_string(char target[], size_t len, const char *source, bool allow_a_chars) {
        assert(target || len == 0);

        if (source) {
                if (!iso9660_valid_string(source, allow_a_chars))
                        return -EINVAL;

                size_t slen = strlen(source);
                if (slen > len)
                        return -EINVAL;

                memset(mempcpy(target, source, slen), ' ', len - slen);
        } else
                memset(target, ' ', len);

        return 0;
}

bool iso9660_volume_name_valid(const char *name) {
        /* In theory the volume identifier should be d-chars, but in practice, a-chars are allowed */
        return iso9660_valid_string(name, /* allow_a_chars= */ true) &&
                strlen(name) <= 32;
}

bool iso9660_system_name_valid(const char *name) {
        return iso9660_valid_string(name, /* allow_a_chars= */ true) &&
                strlen(name) <= 32;
}

bool iso9660_publisher_name_valid(const char *name) {
        return iso9660_valid_string(name, /* allow_a_chars= */ true) &&
                strlen(name) <= 128;
}
