/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>

#include "sd-daemon.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "id128-util.h"
#include "macro.h"
#include "string-util.h"
#include "util.h"

#define ID128_WALDI SD_ID128_MAKE(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10)
#define STR_WALDI "0102030405060708090a0b0c0d0e0f10"
#define UUID_WALDI "01020304-0506-0708-090a-0b0c0d0e0f10"

int main(int argc, char *argv[]) {
        sd_id128_t id, id2;
        char t[33], q[37];
        _cleanup_free_ char *b = NULL;
        _cleanup_close_ int fd = -1;

        assert_se(sd_id128_randomize(&id) == 0);
        printf("random: %s\n", sd_id128_to_string(id, t));

        assert_se(sd_id128_from_string(t, &id2) == 0);
        assert_se(sd_id128_equal(id, id2));

        if (sd_booted() > 0) {
                assert_se(sd_id128_get_machine(&id) == 0);
                printf("machine: %s\n", sd_id128_to_string(id, t));

                assert_se(sd_id128_get_boot(&id) == 0);
                printf("boot: %s\n", sd_id128_to_string(id, t));
        }

        printf("waldi: %s\n", sd_id128_to_string(ID128_WALDI, t));
        assert_se(streq(t, STR_WALDI));

        assert_se(asprintf(&b, SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(ID128_WALDI)) == 32);
        printf("waldi2: %s\n", b);
        assert_se(streq(t, b));

        printf("waldi3: %s\n", id128_to_uuid_string(ID128_WALDI, q));
        assert_se(streq(q, UUID_WALDI));

        b = mfree(b);
        assert_se(asprintf(&b, ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(ID128_WALDI)) == 36);
        printf("waldi4: %s\n", b);
        assert_se(streq(q, b));

        assert_se(sd_id128_from_string(STR_WALDI, &id) >= 0);
        assert_se(sd_id128_equal(id, ID128_WALDI));

        assert_se(sd_id128_from_string(UUID_WALDI, &id) >= 0);
        assert_se(sd_id128_equal(id, ID128_WALDI));

        assert_se(sd_id128_from_string("", &id) < 0);
        assert_se(sd_id128_from_string("01020304-0506-0708-090a-0b0c0d0e0f101", &id) < 0);
        assert_se(sd_id128_from_string("01020304-0506-0708-090a-0b0c0d0e0f10-", &id) < 0);
        assert_se(sd_id128_from_string("01020304-0506-0708-090a0b0c0d0e0f10", &id) < 0);
        assert_se(sd_id128_from_string("010203040506-0708-090a-0b0c0d0e0f10", &id) < 0);

        assert_se(id128_is_valid(STR_WALDI));
        assert_se(id128_is_valid(UUID_WALDI));
        assert_se(!id128_is_valid(""));
        assert_se(!id128_is_valid("01020304-0506-0708-090a-0b0c0d0e0f101"));
        assert_se(!id128_is_valid("01020304-0506-0708-090a-0b0c0d0e0f10-"));
        assert_se(!id128_is_valid("01020304-0506-0708-090a0b0c0d0e0f10"));
        assert_se(!id128_is_valid("010203040506-0708-090a-0b0c0d0e0f10"));

        fd = open_tmpfile_unlinkable(NULL, O_RDWR|O_CLOEXEC);
        assert_se(fd >= 0);

        /* First, write as UUID */
        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(id128_write_fd(fd, ID128_UUID, id, false) >= 0);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_PLAIN, &id2) == -EINVAL);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_UUID, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_ANY, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        /* Second, write as plain */
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(id128_write_fd(fd, ID128_PLAIN, id, false) >= 0);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_UUID, &id2) == -EINVAL);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_PLAIN, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_ANY, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        /* Third, write plain without trailing newline */
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(write(fd, sd_id128_to_string(id, t), 32) == 32);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_UUID, &id2) == -EINVAL);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_PLAIN, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        /* Third, write UUID without trailing newline */
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(write(fd, id128_to_uuid_string(id, t), 36) == 36);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_PLAIN, &id2) == -EINVAL);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_UUID, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        return 0;
}
