/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iso9660.h"
#include "log.h"
#include "stdio-util.h"
#include "string-util.h"

void no_iso9660_datetime(struct iso9660_datetime *ret) {
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

int time_to_iso9660_datetime(const struct tm *t, struct iso9660_datetime *ret) {
        assert(t);
        assert(ret);

        struct tm copy_t = *t;
        if (timegm(&copy_t) == (time_t) -1)
                return -EINVAL;

        if (copy_t.tm_sec != t->tm_sec ||
            copy_t.tm_min != t->tm_min ||
            copy_t.tm_hour != t->tm_hour ||
            copy_t.tm_mday != t->tm_mday ||
            copy_t.tm_mon  != t->tm_mon  ||
            copy_t.tm_year != t->tm_year)
                return -EINVAL;

        if (t->tm_year >= 10000 - 1900)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Year has more than 4 digits and is incompatible with ISO9660.");
        if (t->tm_year + 1900 < 0)
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Year is negative and is incompatible with ISO9660.");

        char buf[17];
        /* Ignore leap seconds, no real hope for hardware. Deci-seconds always zero. */
        xsprintf(buf, "%04d%02d%02d%02d%02d%02d00",
                 t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                 t->tm_hour, t->tm_min, MIN(t->tm_sec, 59));
        memcpy(ret, buf, 16);

        ret->zone = t->tm_gmtoff / (15*60);

        return 0;
}

int time_to_iso9660_dir_datetime(const struct tm *t, struct iso9660_dir_time *ret) {
        assert(t);
        assert(ret);

        struct tm copy_t = *t;
        if (timegm(&copy_t) == (time_t) -1)
                return -EINVAL;

        if (copy_t.tm_sec != t->tm_sec ||
            copy_t.tm_min != t->tm_min ||
            copy_t.tm_hour != t->tm_hour ||
            copy_t.tm_mday != t->tm_mday ||
            copy_t.tm_mon  != t->tm_mon  ||
            copy_t.tm_year != t->tm_year)
                return -EINVAL;

        if (t->tm_year < 0 || t->tm_year > UINT8_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Year is incompatible with ISO9660.");

        *ret = (struct iso9660_dir_time) {
                .year = t->tm_year,
                .month = t->tm_mon + 1,
                .day = t->tm_mday,
                .hour = t->tm_hour,
                .minute = t->tm_min,
                .second = MIN(t->tm_sec, 59),
                .offset = t->tm_gmtoff / (15*60),
        };

        return 0;
}

static bool valid_iso9660_string(const char *str, bool allow_a_chars) {
        /* note that a-chars are not supposed to accept lower case letters, but it looks like common practice
         * to use them
         */
        return in_charset(str, allow_a_chars ? UPPERCASE_LETTERS LOWERCASE_LETTERS DIGITS " _!\"%&'()*+,-./:;<=>?" : UPPERCASE_LETTERS DIGITS "_");
}

int set_iso9660_string(char target[], size_t len, const char *source, bool allow_a_chars) {
        if (source && !valid_iso9660_string(source, allow_a_chars))
                return -EINVAL;

        if (source) {
                size_t slen = strlen(source);
                if (slen > len)
                        return -EINVAL;
                void* p = mempcpy(target, source, slen);
                memset(p, ' ', len - slen);
        } else
                memset(target, ' ', len);

        return 0;
}

bool iso9660_volume_name_valid(const char* name) {
        /* In theory the volume identifier should be d-chars, but in practice, a-chars are allowed */
        return valid_iso9660_string(name, /* allow_a_chars= */ true) &&
                strlen(name) <= 32;
}

bool iso9660_system_name_valid(const char* name) {
        return valid_iso9660_string(name, /* allow_a_chars= */ true) &&
                strlen(name) <= 32;
}

bool iso9660_publisher_name_valid(const char* name) {
        return valid_iso9660_string(name, /* allow_a_chars= */ true) &&
                strlen(name) <= 128;
}
