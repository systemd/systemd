/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "id128-util.h"
#include "macro.h"
#include "path-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "tmpfile-util.h"

#define ID128_WALDI SD_ID128_MAKE(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10)
#define STR_WALDI "0102030405060708090a0b0c0d0e0f10"
#define UUID_WALDI "01020304-0506-0708-090a-0b0c0d0e0f10"
#define STR_NULL "00000000000000000000000000000000"

TEST(id128) {
        sd_id128_t id, id2;
        char t[SD_ID128_STRING_MAX], q[SD_ID128_UUID_STRING_MAX];
        _cleanup_free_ char *b = NULL;
        _cleanup_close_ int fd = -EBADF;

        assert_se(sd_id128_randomize(&id) == 0);
        printf("random: %s\n", sd_id128_to_string(id, t));

        assert_se(sd_id128_from_string(t, &id2) == 0);
        assert_se(sd_id128_equal(id, id2));
        assert_se(sd_id128_in_set(id, id));
        assert_se(sd_id128_in_set(id, id2));
        assert_se(sd_id128_in_set(id, id2, id));
        assert_se(sd_id128_in_set(id, ID128_WALDI, id));
        assert_se(!sd_id128_in_set(id));
        assert_se(!sd_id128_in_set(id, ID128_WALDI));
        assert_se(!sd_id128_in_set(id, ID128_WALDI, ID128_WALDI));

        if (sd_booted() > 0 && sd_id128_get_machine(NULL) >= 0) {
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

        printf("waldi3: %s\n", sd_id128_to_uuid_string(ID128_WALDI, q));
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

        assert_se(id128_from_string_nonzero(STR_WALDI, &id) == 0);
        assert_se(id128_from_string_nonzero(STR_NULL, &id) == -ENXIO);
        assert_se(id128_from_string_nonzero("01020304-0506-0708-090a-0b0c0d0e0f101", &id) < 0);
        assert_se(id128_from_string_nonzero("01020304-0506-0708-090a-0b0c0d0e0f10-", &id) < 0);
        assert_se(id128_from_string_nonzero("01020304-0506-0708-090a0b0c0d0e0f10", &id) < 0);
        assert_se(id128_from_string_nonzero("010203040506-0708-090a-0b0c0d0e0f10", &id) < 0);

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
        assert_se(id128_write_fd(fd, ID128_FORMAT_UUID, id) >= 0);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_PLAIN, &id2) == -EUCLEAN);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_UUID, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_ANY, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        /* Second, write as plain */
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(id128_write_fd(fd, ID128_FORMAT_PLAIN, id) >= 0);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_UUID, &id2) == -EUCLEAN);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_PLAIN, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_ANY, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        /* Third, write plain without trailing newline */
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(write(fd, sd_id128_to_string(id, t), 32) == 32);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_UUID, &id2) == -EUCLEAN);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_PLAIN, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        /* Fourth, write UUID without trailing newline */
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);

        assert_se(sd_id128_randomize(&id) >= 0);
        assert_se(write(fd, sd_id128_to_uuid_string(id, q), 36) == 36);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_PLAIN, &id2) == -EUCLEAN);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_UUID, &id2) >= 0);
        assert_se(sd_id128_equal(id, id2));

        /* Fifth, tests for "uninitialized" */
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);
        assert_se(write(fd, "uninitialized", STRLEN("uninitialized")) == STRLEN("uninitialized"));
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_ANY, NULL) == -ENOPKG);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);
        assert_se(write(fd, "uninitialized\n", STRLEN("uninitialized\n")) == STRLEN("uninitialized\n"));
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_ANY, NULL) == -ENOPKG);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);
        assert_se(write(fd, "uninitialized\nfoo", STRLEN("uninitialized\nfoo")) == STRLEN("uninitialized\nfoo"));
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_ANY, NULL) == -EUCLEAN);

        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(ftruncate(fd, 0) >= 0);
        assert_se(write(fd, "uninit", STRLEN("uninit")) == STRLEN("uninit"));
        assert_se(lseek(fd, 0, SEEK_SET) == 0);
        assert_se(id128_read_fd(fd, ID128_FORMAT_ANY, NULL) == -EUCLEAN);

        /* build/systemd-id128 -a f03daaeb1c334b43a732172944bf772e show 51df0b4bc3b04c9780e299b98ca373b8 */
        assert_se(sd_id128_get_app_specific(SD_ID128_MAKE(51,df,0b,4b,c3,b0,4c,97,80,e2,99,b9,8c,a3,73,b8),
                                            SD_ID128_MAKE(f0,3d,aa,eb,1c,33,4b,43,a7,32,17,29,44,bf,77,2e), &id) >= 0);
        assert_se(sd_id128_equal(id, SD_ID128_MAKE(1d,ee,59,54,e7,5c,4d,6f,b9,6c,c6,c0,4c,a1,8a,86)));

        if (sd_booted() > 0 && sd_id128_get_machine(NULL) >= 0) {
                assert_se(sd_id128_get_machine_app_specific(SD_ID128_MAKE(f0,3d,aa,eb,1c,33,4b,43,a7,32,17,29,44,bf,77,2e), &id) >= 0);
                assert_se(sd_id128_get_machine_app_specific(SD_ID128_MAKE(f0,3d,aa,eb,1c,33,4b,43,a7,32,17,29,44,bf,77,2e), &id2) >= 0);
                assert_se(sd_id128_equal(id, id2));
                assert_se(sd_id128_get_machine_app_specific(SD_ID128_MAKE(51,df,0b,4b,c3,b0,4c,97,80,e2,99,b9,8c,a3,73,b8), &id2) >= 0);
                assert_se(!sd_id128_equal(id, id2));
        }

        /* Check return values */
        ASSERT_RETURN_EXPECTED_SE(sd_id128_get_app_specific(SD_ID128_ALLF, SD_ID128_NULL, &id) == -ENXIO);
        ASSERT_RETURN_EXPECTED_SE(sd_id128_get_app_specific(SD_ID128_NULL, SD_ID128_ALLF, &id) == 0);
}

TEST(sd_id128_get_invocation) {
        sd_id128_t id;
        int r;

        /* Query the invocation ID */
        r = sd_id128_get_invocation(&id);
        if (r < 0)
                log_warning_errno(r, "Failed to get invocation ID, ignoring: %m");
        else
                log_info("Invocation ID: " SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));
}

TEST(benchmark_sd_id128_get_machine_app_specific) {
        unsigned iterations = slow_tests_enabled() ? 1000000 : 1000;
        usec_t t, q;

        if (sd_id128_get_machine(NULL) < 0)
                return (void) log_tests_skipped("/etc/machine-id is not initialized");

        log_info("/* %s (%u iterations) */", __func__, iterations);

        sd_id128_t id = ID128_WALDI, id2;

        t = now(CLOCK_MONOTONIC);

        for (unsigned i = 0; i < iterations; i++) {
                id.qwords[1] = i;

                assert_se(sd_id128_get_machine_app_specific(id, &id2) >= 0);
        }

        q = now(CLOCK_MONOTONIC) - t;

        log_info("%lf μs each", (double) q / iterations);
}

TEST(id128_at) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        _cleanup_free_ char *p = NULL;
        sd_id128_t id, i;

        tfd = mkdtemp_open(NULL, O_PATH, &t);
        assert_se(tfd >= 0);
        assert_se(mkdirat(tfd, "etc", 0755) >= 0);
        assert_se(symlinkat("etc", tfd, "etc2") >= 0);
        assert_se(symlinkat("machine-id", tfd, "etc/hoge-id") >= 0);

        assert_se(sd_id128_randomize(&id) == 0);

        assert_se(id128_write_at(tfd, "etc/machine-id", ID128_FORMAT_PLAIN, id) >= 0);
        if (geteuid() == 0)
                assert_se(id128_write_at(tfd, "etc/machine-id", ID128_FORMAT_PLAIN, id) >= 0);
        else
                assert_se(id128_write_at(tfd, "etc/machine-id", ID128_FORMAT_PLAIN, id) == -EACCES);
        assert_se(unlinkat(tfd, "etc/machine-id", 0) >= 0);
        assert_se(id128_write_at(tfd, "etc2/machine-id", ID128_FORMAT_PLAIN, id) >= 0);
        assert_se(unlinkat(tfd, "etc/machine-id", 0) >= 0);
        assert_se(id128_write_at(tfd, "etc/hoge-id", ID128_FORMAT_PLAIN, id) >= 0);
        assert_se(unlinkat(tfd, "etc/machine-id", 0) >= 0);
        assert_se(id128_write_at(tfd, "etc2/hoge-id", ID128_FORMAT_PLAIN, id) >= 0);

        /* id128_read_at() */
        i = SD_ID128_NULL; /* Not necessary in real code, but for testing that the id is really assigned. */
        assert_se(id128_read_at(tfd, "etc/machine-id", ID128_FORMAT_PLAIN, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        i = SD_ID128_NULL;
        assert_se(id128_read_at(tfd, "etc2/machine-id", ID128_FORMAT_PLAIN, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        i = SD_ID128_NULL;
        assert_se(id128_read_at(tfd, "etc/hoge-id", ID128_FORMAT_PLAIN, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        i = SD_ID128_NULL;
        assert_se(id128_read_at(tfd, "etc2/hoge-id", ID128_FORMAT_PLAIN, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        /* id128_read() */
        assert_se(p = path_join(t, "/etc/machine-id"));

        i = SD_ID128_NULL;
        assert_se(id128_read(p, ID128_FORMAT_PLAIN, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        free(p);
        assert_se(p = path_join(t, "/etc2/machine-id"));

        i = SD_ID128_NULL;
        assert_se(id128_read(p, ID128_FORMAT_PLAIN, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        free(p);
        assert_se(p = path_join(t, "/etc/hoge-id"));

        i = SD_ID128_NULL;
        assert_se(id128_read(p, ID128_FORMAT_PLAIN, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        free(p);
        assert_se(p = path_join(t, "/etc2/hoge-id"));

        i = SD_ID128_NULL;
        assert_se(id128_read(p, ID128_FORMAT_PLAIN, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        /* id128_get_machine_at() */
        i = SD_ID128_NULL;
        assert_se(id128_get_machine_at(tfd, &i) >= 0);
        assert_se(sd_id128_equal(id, i));

        /* id128_get_machine() */
        i = SD_ID128_NULL;
        assert_se(id128_get_machine(t, &i) >= 0);
        assert_se(sd_id128_equal(id, i));
}

TEST(ID128_REFUSE_NULL) {
        _cleanup_(rm_rf_physical_and_freep) char *t = NULL;
        _cleanup_close_ int tfd = -EBADF;
        sd_id128_t id;

        tfd = mkdtemp_open(NULL, O_PATH, &t);
        assert_se(tfd >= 0);

        assert_se(id128_write_at(tfd, "zero-id", ID128_FORMAT_PLAIN | ID128_REFUSE_NULL, (sd_id128_t) {}) == -ENOMEDIUM);
        assert_se(unlinkat(tfd, "zero-id", 0) >= 0);
        assert_se(id128_write_at(tfd, "zero-id", ID128_FORMAT_PLAIN, (sd_id128_t) {}) >= 0);

        assert_se(sd_id128_randomize(&id) == 0);
        assert_se(!sd_id128_equal(id, SD_ID128_NULL));
        assert_se(id128_read_at(tfd, "zero-id", ID128_FORMAT_PLAIN, &id) >= 0);
        assert_se(sd_id128_equal(id, SD_ID128_NULL));

        assert_se(id128_read_at(tfd, "zero-id", ID128_FORMAT_PLAIN | ID128_REFUSE_NULL, &id) == -ENOMEDIUM);
}

DEFINE_TEST_MAIN(LOG_INFO);
