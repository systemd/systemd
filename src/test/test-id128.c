/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "id128-util.h"
#include "macro.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "util.h"

#define ID128_WALDI SD_ID128_MAKE(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10)
#define STR_WALDI "0102030405060708090a0b0c0d0e0f10"
#define UUID_WALDI "01020304-0506-0708-090a-0b0c0d0e0f10"

int main(int argc, char *argv[]) {
        sd_id128_t id, id2;
        char t[33], q[37];
        _cleanup_free_ char *b = NULL;
        _cleanup_close_ int fd = -1;
        int r;

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
        assert_se(asprintf(&b, SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(ID128_WALDI)) == 36);
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
        assert_se(write(fd, id128_to_uuid_string(id, q), 36) == 36);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_PLAIN, &id2) == -EINVAL);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_UUID, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        r = sd_id128_get_machine_app_specific(SD_ID128_MAKE(f0,3d,aa,eb,1c,33,4b,43,a7,32,17,29,44,bf,77,2e), &id);
        if (r == -EOPNOTSUPP)
                log_info("khash not supported on this kernel, skipping sd_id128_get_machine_app_specific() checks");
        else {
                assert_se(r >= 0);
                assert_se(sd_id128_get_machine_app_specific(SD_ID128_MAKE(f0,3d,aa,eb,1c,33,4b,43,a7,32,17,29,44,bf,77,2e), &id2) >= 0);
                assert_se(sd_id128_equal(id, id2));
                assert_se(sd_id128_get_machine_app_specific(SD_ID128_MAKE(51,df,0b,4b,c3,b0,4c,97,80,e2,99,b9,8c,a3,73,b8), &id2) >= 0);
                assert_se(!sd_id128_equal(id, id2));
        }

        /* Query the invocation ID */
        r = sd_id128_get_invocation(&id);
        if (r < 0)
                log_warning_errno(r, "Failed to get invocation ID, ignoring: %m");
        else
                log_info("Invocation ID: " SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));

        return 0;
}
