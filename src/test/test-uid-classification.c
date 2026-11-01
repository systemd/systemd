/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "uid-classification.h"

static void test_read_login_defs_one(const char *path) {
        log_info("/* %s(\"%s\") */", __func__, path ?: "<custom>");

        _cleanup_(unlink_tempfilep) char name[] = "/tmp/test-user-record.XXXXXX";
        _cleanup_fclose_ FILE *f = NULL;
        if (!path) {
                ASSERT_OK_ZERO(fmkostemp_safe(name, "r+", &f));
                fprintf(f,
                        "SYS_UID_MIN "UID_FMT"\n"
                        "SYS_UID_MAX "UID_FMT"\n"
                        "SYS_GID_MIN "GID_FMT"\n"
                        "SYS_GID_MAX "GID_FMT"\n",
                        (uid_t) (SYSTEM_ALLOC_UID_MIN + 5),
                        (uid_t) (SYSTEM_UID_MAX + 5),
                        (gid_t) (SYSTEM_ALLOC_GID_MIN + 5),
                        (gid_t) (SYSTEM_GID_MAX + 5));
                ASSERT_OK(fflush_and_check(f));
        }

        UGIDAllocationRange defs;
        ASSERT_OK(read_login_defs(&defs, path ?: name, /* root= */ NULL));

        log_info("system_alloc_uid_min="UID_FMT, defs.system_alloc_uid_min);
        log_info("system_uid_max="UID_FMT, defs.system_uid_max);
        log_info("system_alloc_gid_min="GID_FMT, defs.system_alloc_gid_min);
        log_info("system_gid_max="GID_FMT, defs.system_gid_max);

        if (!path) {
                uid_t offset = ENABLE_COMPAT_MUTABLE_UID_BOUNDARIES ? 5 : 0;
                ASSERT_EQ(defs.system_alloc_uid_min, SYSTEM_ALLOC_UID_MIN + offset);
                ASSERT_EQ(defs.system_uid_max, SYSTEM_UID_MAX + offset);
                ASSERT_EQ(defs.system_alloc_gid_min, SYSTEM_ALLOC_GID_MIN + offset);
                ASSERT_EQ(defs.system_gid_max, SYSTEM_GID_MAX + offset);
        } else if (streq(path, "/dev/null")) {
                ASSERT_EQ(defs.system_alloc_uid_min, (uid_t) SYSTEM_ALLOC_UID_MIN);
                ASSERT_EQ(defs.system_uid_max, (uid_t) SYSTEM_UID_MAX);
                ASSERT_EQ(defs.system_alloc_gid_min, (gid_t) SYSTEM_ALLOC_GID_MIN);
                ASSERT_EQ(defs.system_gid_max, (gid_t) SYSTEM_GID_MAX);
        }
}

TEST(read_login_defs) {
        test_read_login_defs_one("/dev/null");
        test_read_login_defs_one("/etc/login.defs");
        test_read_login_defs_one(/* path= */ NULL);
}

TEST(acquire_ugid_allocation_range) {
        const UGIDAllocationRange *defs;
        ASSERT_NOT_NULL(defs = acquire_ugid_allocation_range());

        log_info("system_alloc_uid_min="UID_FMT, defs->system_alloc_uid_min);
        log_info("system_uid_max="UID_FMT, defs->system_uid_max);
        log_info("system_alloc_gid_min="GID_FMT, defs->system_alloc_gid_min);
        log_info("system_gid_max="GID_FMT, defs->system_gid_max);
}

TEST(uid_is_system) {
        uid_t uid = 0;
        log_info("uid_is_system("UID_FMT") = %s", uid, yes_no(uid_is_system(uid)));

        uid = 999;
        log_info("uid_is_system("UID_FMT") = %s", uid, yes_no(uid_is_system(uid)));

        uid = getuid();
        log_info("uid_is_system("UID_FMT") = %s", uid, yes_no(uid_is_system(uid)));
}

TEST(gid_is_system) {
        gid_t gid = 0;
        log_info("gid_is_system("GID_FMT") = %s", gid, yes_no(gid_is_system(gid)));

        gid = 999;
        log_info("gid_is_system("GID_FMT") = %s", gid, yes_no(gid_is_system(gid)));

        gid = getgid();
        log_info("gid_is_system("GID_FMT") = %s", gid, yes_no(gid_is_system(gid)));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
