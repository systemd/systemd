/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <inttypes.h>
#include <linux/fiemap.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "efivars.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "memory-util.h"
#include "sleep-config.h"
#include "strv.h"
#include "tests.h"
#include "util.h"

TEST(parse_sleep_config) {
        _cleanup_(free_sleep_configp) SleepConfig *sleep_config = NULL;

        assert_se(parse_sleep_config(&sleep_config) == 0);

        _cleanup_free_ char *sum, *sus, *him, *his, *hym, *hys;

        sum = strv_join(sleep_config->modes[SLEEP_SUSPEND], ", ");
        sus = strv_join(sleep_config->states[SLEEP_SUSPEND], ", ");
        him = strv_join(sleep_config->modes[SLEEP_HIBERNATE], ", ");
        his = strv_join(sleep_config->states[SLEEP_HIBERNATE], ", ");
        hym = strv_join(sleep_config->modes[SLEEP_HYBRID_SLEEP], ", ");
        hys = strv_join(sleep_config->states[SLEEP_HYBRID_SLEEP], ", ");
        log_debug("  allow_suspend: %u", sleep_config->allow[SLEEP_SUSPEND]);
        log_debug("  allow_hibernate: %u", sleep_config->allow[SLEEP_HIBERNATE]);
        log_debug("  allow_s2h: %u", sleep_config->allow[SLEEP_SUSPEND_THEN_HIBERNATE]);
        log_debug("  allow_hybrid_sleep: %u", sleep_config->allow[SLEEP_HYBRID_SLEEP]);
        log_debug("  suspend modes: %s", sum);
        log_debug("         states: %s", sus);
        log_debug("  hibernate modes: %s", him);
        log_debug("           states: %s", his);
        log_debug("  hybrid modes: %s", hym);
        log_debug("        states: %s", hys);
}

static int test_fiemap_one(const char *path) {
        _cleanup_free_ struct fiemap *fiemap = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        log_info("/* %s */", __func__);

        fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return log_error_errno(errno, "failed to open %s: %m", path);
        r = read_fiemap(fd, &fiemap);
        if (r == -EOPNOTSUPP)
                exit(log_tests_skipped("Not supported"));
        if (r < 0)
                return log_error_errno(r, "Unable to read extent map for '%s': %m", path);
        log_info("extent map information for %s:", path);
        log_info("\t start: %" PRIu64, (uint64_t) fiemap->fm_start);
        log_info("\t length: %" PRIu64, (uint64_t) fiemap->fm_length);
        log_info("\t flags: %" PRIu32, fiemap->fm_flags);
        log_info("\t number of mapped extents: %" PRIu32, fiemap->fm_mapped_extents);
        log_info("\t extent count: %" PRIu32, fiemap->fm_extent_count);
        if (fiemap->fm_extent_count > 0)
                log_info("\t first extent location: %" PRIu64,
                         (uint64_t) (fiemap->fm_extents[0].fe_physical / page_size()));

        return 0;
}

TEST_RET(fiemap) {
        int r = 0;

        assert_se(test_fiemap_one(saved_argv[0]) == 0);
        for (int i = 1; i < saved_argc; i++) {
                int k = test_fiemap_one(saved_argv[i]);
                if (r == 0)
                        r = k;
        }

        return r;
}

TEST(sleep) {
        _cleanup_strv_free_ char
                **standby = strv_new("standby"),
                **mem = strv_new("mem"),
                **disk = strv_new("disk"),
                **suspend = strv_new("suspend"),
                **reboot = strv_new("reboot"),
                **platform = strv_new("platform"),
                **shutdown = strv_new("shutdown"),
                **freeze = strv_new("freeze");
        int r;

        printf("Secure boot: %sd\n", enable_disable(is_efi_secure_boot()));

        log_info("/= individual sleep modes =/");
        log_info("Standby configured: %s", yes_no(can_sleep_state(standby) > 0));
        log_info("Suspend configured: %s", yes_no(can_sleep_state(mem) > 0));
        log_info("Hibernate configured: %s", yes_no(can_sleep_state(disk) > 0));
        log_info("Hibernate+Suspend (Hybrid-Sleep) configured: %s", yes_no(can_sleep_disk(suspend) > 0));
        log_info("Hibernate+Reboot configured: %s", yes_no(can_sleep_disk(reboot) > 0));
        log_info("Hibernate+Platform configured: %s", yes_no(can_sleep_disk(platform) > 0));
        log_info("Hibernate+Shutdown configured: %s", yes_no(can_sleep_disk(shutdown) > 0));
        log_info("Freeze configured: %s", yes_no(can_sleep_state(freeze) > 0));

        log_info("/= high-level sleep verbs =/");
        r = can_sleep(SLEEP_SUSPEND);
        log_info("Suspend configured and possible: %s", r >= 0 ? yes_no(r) : strerror_safe(r));
        r = can_sleep(SLEEP_HIBERNATE);
        log_info("Hibernation configured and possible: %s", r >= 0 ? yes_no(r) : strerror_safe(r));
        r = can_sleep(SLEEP_HYBRID_SLEEP);
        log_info("Hybrid-sleep configured and possible: %s", r >= 0 ? yes_no(r) : strerror_safe(r));
        r = can_sleep(SLEEP_SUSPEND_THEN_HIBERNATE);
        log_info("Suspend-then-Hibernate configured and possible: %s", r >= 0 ? yes_no(r) : strerror_safe(r));
}

DEFINE_CUSTOM_TEST_MAIN(
        LOG_DEBUG,
        ({
                if (getuid() != 0)
                        log_warning("This program is unlikely to work for unprivileged users");
        }),
        /* no outro */);
