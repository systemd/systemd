/* SPDX-License-Identifier: LGPL-2.1+ */

#include <unistd.h>
#include <sys/types.h>

#include "format-util.h"
#include "tests.h"
#include "user-record.h"

static void test_acquire_ugid_allocation_range(void) {
        log_info("/* %s */", __func__);

        const UGIDAllocationRange *defs;
        assert_se(defs = acquire_ugid_allocation_range());

        log_info("system_uid_max="UID_FMT, defs->system_uid_max);
        log_info("system_gid_max="GID_FMT, defs->system_gid_max);
}

static void test_uid_is_system(void) {
        log_info("/* %s */", __func__);

        uid_t uid = 0;
        log_info("uid_is_system("UID_FMT") = %s", uid, yes_no(uid_is_system(uid)));

        uid = 999;
        log_info("uid_is_system("UID_FMT") = %s", uid, yes_no(uid_is_system(uid)));

        uid = getuid();
        log_info("uid_is_system("UID_FMT") = %s", uid, yes_no(uid_is_system(uid)));
}

static void test_gid_is_system(void) {
        log_info("/* %s */", __func__);

        gid_t gid = 0;
        log_info("gid_is_system("GID_FMT") = %s", gid, yes_no(gid_is_system(gid)));

        gid = 999;
        log_info("gid_is_system("GID_FMT") = %s", gid, yes_no(gid_is_system(gid)));

        gid = getgid();
        log_info("gid_is_system("GID_FMT") = %s", gid, yes_no(gid_is_system(gid)));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_acquire_ugid_allocation_range();
        test_uid_is_system();
        test_gid_is_system();

        return 0;
}
