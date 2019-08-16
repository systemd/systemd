/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <inttypes.h>
#include <linux/fiemap.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "memory-util.h"
#include "sleep-config.h"
#include "strv.h"
#include "tests.h"
#include "util.h"

static void test_parse_sleep_config(void) {
        _cleanup_(free_sleep_configp) SleepConfig *sleep_config = NULL;
        log_info("/* %s */", __func__);

        assert(parse_sleep_config(&sleep_config) == 0);

        _cleanup_free_ char *sum, *sus, *him, *his, *hym, *hys;

        sum = strv_join(sleep_config->suspend_modes, ", ");
        sus = strv_join(sleep_config->suspend_states, ", ");
        him = strv_join(sleep_config->hibernate_modes, ", ");
        his = strv_join(sleep_config->hibernate_states, ", ");
        hym = strv_join(sleep_config->hybrid_modes, ", ");
        hys = strv_join(sleep_config->hybrid_states, ", ");
        log_debug("  allow_suspend: %u", sleep_config->allow_suspend);
        log_debug("  allow_hibernate: %u", sleep_config->allow_hibernate);
        log_debug("  allow_s2h: %u", sleep_config->allow_s2h);
        log_debug("  allow_hybrid_sleep: %u", sleep_config->allow_hybrid_sleep);
        log_debug("  suspend modes: %s", sum);
        log_debug("         states: %s", sus);
        log_debug("  hibernate modes: %s", him);
        log_debug("           states: %s", his);
        log_debug("  hybrid modes: %s", hym);
        log_debug("        states: %s", hys);
}

static int test_fiemap(const char *path) {
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

static void test_sleep(void) {
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

        log_info("/* %s */", __func__);

        log_info("/= configuration =/");
        log_info("Standby configured: %s", yes_no(can_sleep_state(standby) > 0));
        log_info("Suspend configured: %s", yes_no(can_sleep_state(mem) > 0));
        log_info("Hibernate configured: %s", yes_no(can_sleep_state(disk) > 0));
        log_info("Hibernate+Suspend (Hybrid-Sleep) configured: %s", yes_no(can_sleep_disk(suspend) > 0));
        log_info("Hibernate+Reboot configured: %s", yes_no(can_sleep_disk(reboot) > 0));
        log_info("Hibernate+Platform configured: %s", yes_no(can_sleep_disk(platform) > 0));
        log_info("Hibernate+Shutdown configured: %s", yes_no(can_sleep_disk(shutdown) > 0));
        log_info("Freeze configured: %s", yes_no(can_sleep_state(freeze) > 0));

        log_info("/= running system =/");
        r = can_sleep("suspend");
        log_info("Suspend configured and possible: %s", r >= 0 ? yes_no(r) : strerror_safe(r));
        r = can_sleep("hibernate");
        log_info("Hibernation configured and possible: %s", r >= 0 ? yes_no(r) : strerror_safe(r));
        r = can_sleep("hybrid-sleep");
        log_info("Hybrid-sleep configured and possible: %s", r >= 0 ? yes_no(r) : strerror_safe(r));
        r = can_sleep("suspend-then-hibernate");
        log_info("Suspend-then-Hibernate configured and possible: %s", r >= 0 ? yes_no(r) : strerror_safe(r));
}

int main(int argc, char* argv[]) {
        int i, r = 0, k;

        test_setup_logging(LOG_DEBUG);

        if (getuid() != 0)
                log_warning("This program is unlikely to work for unprivileged users");

        test_parse_sleep_config();
        test_sleep();

        if (argc <= 1)
                assert_se(test_fiemap(argv[0]) == 0);
        else
                for (i = 1; i < argc; i++) {
                        k = test_fiemap(argv[i]);
                        if (r == 0)
                                r = k;
                }

        return r;
}
