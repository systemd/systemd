/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>

#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "log.h"
#include "mkdir.h"
#include "missing.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "udev.h"

static const struct fakefs {
        const char *target;
        bool ignore_mount_error;
} fakefss[] = {
        { "/sys",                    false },
        { "/dev",                    false },
        { "/run",                    false },
        { "/etc",                    false },
        { UDEVLIBEXECDIR "/rules.d", true },
};

static int setup_mount_namespace(void) {
        static thread_local bool is_namespaced = false;

        if (is_namespaced)
                return 1;

        if (unshare(CLONE_NEWNS) < 0)
                return log_error_errno(errno, "Failed to call unshare(): %m");

        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                return log_error_errno(errno, "Failed to mount / as private: %m");

        is_namespaced = true;

        return 1;
}

static int setup_fake_filesystems(const char *runtime_dir) {
        for (unsigned i = 0; i < ELEMENTSOF(fakefss); i++)
                if (mount(runtime_dir, fakefss[i].target, NULL, MS_BIND, NULL) < 0) {
                        log_full_errno(fakefss[i].ignore_mount_error ? LOG_DEBUG : LOG_ERR, errno, "Failed to mount %s: %m", fakefss[i].target);
                        if (!fakefss[i].ignore_mount_error)
                                return -errno;
                }

        return 0;
}

static int cleanup_fake_filesystems(const char *runtime_dir) {
        for (unsigned i = 0; i < ELEMENTSOF(fakefss); i++)
                if (umount(fakefss[i].target) < 0) {
                        log_full_errno(fakefss[i].ignore_mount_error ? LOG_DEBUG : LOG_ERR, errno, "Failed to umount %s: %m", fakefss[i].target);
                        if (!fakefss[i].ignore_mount_error)
                                return -errno;
                }
        return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(udev_rules_freep) struct udev_rules *rules = NULL;
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL;
        FILE *f = NULL;

        /* To judge from https://oss-fuzz.com/testcase?key=5642013043589120, unshare/mount can fail.
         * It isn't critical so let's ignore it for now to see how it goes */
        (void) setup_mount_namespace();

        assert_se(runtime_dir = setup_fake_runtime_dir());

        if (setup_fake_filesystems(runtime_dir) < 0) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
                return EXIT_TEST_SKIP;
#else
                abort();
#endif
        }

        if (!getenv("SYSTEMD_LOG_LEVEL")) {
                log_set_max_level_realm(LOG_REALM_UDEV, LOG_CRIT);
                log_set_max_level_realm(LOG_REALM_SYSTEMD, LOG_CRIT);
        }

        assert_se(mkdir_p("/etc/udev/rules.d", 0755) >= 0);
        f = fopen("/etc/udev/rules.d/fuzz.rules", "we");
        assert_se(f);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);
        assert_se(fclose(f) == 0);
        rules = udev_rules_new(RESOLVE_NAME_EARLY);

        assert_se(cleanup_fake_filesystems(runtime_dir) >= 0);

        return 0;
}
