/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "efivars.h"
#include "errno-util.h"
#include "log.h"
#include "sleep-config.h"
#include "strv.h"
#include "tests.h"

TEST(parse_sleep_config) {
        _cleanup_(sleep_config_freep) SleepConfig *sleep_config = NULL;

        assert_se(parse_sleep_config(&sleep_config) == 0);

        _cleanup_free_ char *sum = NULL, *sus = NULL, *him = NULL, *his = NULL, *hym = NULL, *hys = NULL;

        sum = strv_join(sleep_config->modes[SLEEP_SUSPEND], ", ");
        sus = strv_join(sleep_config->states[SLEEP_SUSPEND], ", ");
        him = strv_join(sleep_config->modes[SLEEP_HIBERNATE], ", ");
        his = strv_join(sleep_config->states[SLEEP_HIBERNATE], ", ");
        hym = strv_join(sleep_config->modes[SLEEP_HYBRID_SLEEP], ", ");
        hys = strv_join(sleep_config->states[SLEEP_HYBRID_SLEEP], ", ");
        log_debug("  allow_suspend: %s", yes_no(sleep_config->allow[SLEEP_SUSPEND]));
        log_debug("  allow_hibernate: %s", yes_no(sleep_config->allow[SLEEP_HIBERNATE]));
        log_debug("  allow_s2h: %s", yes_no(sleep_config->allow[SLEEP_SUSPEND_THEN_HIBERNATE]));
        log_debug("  allow_hybrid_sleep: %s", yes_no(sleep_config->allow[SLEEP_HYBRID_SLEEP]));
        log_debug("  suspend modes: %s", sum);
        log_debug("         states: %s", sus);
        log_debug("  hibernate modes: %s", him);
        log_debug("           states: %s", his);
        log_debug("  hybrid modes: %s", hym);
        log_debug("        states: %s", hys);
}

TEST(sleep_supported) {
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
        log_info("Standby configured: %s", yes_no(sleep_state_supported(standby) > 0));
        log_info("Suspend configured: %s", yes_no(sleep_state_supported(mem) > 0));
        log_info("Hibernate configured: %s", yes_no(sleep_state_supported(disk) > 0));
        log_info("Hibernate+Suspend (Hybrid-Sleep) configured: %s", yes_no(sleep_mode_supported("/sys/power/disk", suspend) > 0));
        log_info("Hibernate+Reboot configured: %s", yes_no(sleep_mode_supported("/sys/power/disk", reboot) > 0));
        log_info("Hibernate+Platform configured: %s", yes_no(sleep_mode_supported("/sys/power/disk", platform) > 0));
        log_info("Hibernate+Shutdown configured: %s", yes_no(sleep_mode_supported("/sys/power/disk", shutdown) > 0));
        log_info("Freeze configured: %s", yes_no(sleep_state_supported(freeze) > 0));

        log_info("/= high-level sleep verbs =/");
        r = sleep_supported(SLEEP_SUSPEND);
        log_info("Suspend configured and possible: %s", r >= 0 ? yes_no(r) : STRERROR(r));
        r = sleep_supported(SLEEP_HIBERNATE);
        log_info("Hibernation configured and possible: %s", r >= 0 ? yes_no(r) : STRERROR(r));
        r = sleep_supported(SLEEP_HYBRID_SLEEP);
        log_info("Hybrid-sleep configured and possible: %s", r >= 0 ? yes_no(r) : STRERROR(r));
        r = sleep_supported(SLEEP_SUSPEND_THEN_HIBERNATE);
        log_info("Suspend-then-Hibernate configured and possible: %s", r >= 0 ? yes_no(r) : STRERROR(r));
}

static int intro(void) {
        if (getuid() != 0)
                log_warning("This program is unlikely to work for unprivileged users");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
