/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-event.h"

#include "device-monitor-private.h"
#include "device-private.h"
#include "device-util.h"
#include "macro.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"
#include "virt.h"

static int monitor_handler(sd_device_monitor *m, sd_device *d, void *userdata) {
        const char *s, *syspath = userdata;

        assert_se(sd_device_get_syspath(d, &s) >= 0);
        assert_se(streq(s, syspath));

        return sd_event_exit(sd_device_monitor_get_event(m), 0);
}

static int test_loopback(bool subsystem_filter, bool tag_filter, bool use_bpf) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL;
        const char *syspath, *subsystem, *tag;
        int r;

        log_info("/* %s(subsystem_filter=%s, tag_filter=%s, use_bpf=%s) */", __func__,
                 true_false(subsystem_filter), true_false(tag_filter), true_false(use_bpf));

        assert_se(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo") >= 0);
        assert_se(sd_device_get_syspath(loopback, &syspath) >= 0);
        assert_se(device_add_property(loopback, "ACTION", "add") >= 0);
        assert_se(device_add_property(loopback, "SEQNUM", "10") >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath, "loopback-monitor") >= 0);

        if (subsystem_filter) {
                assert_se(sd_device_get_subsystem(loopback, &subsystem) >= 0);
                assert_se(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, subsystem, NULL) >= 0);
        }

        if (tag_filter)
                FOREACH_DEVICE_TAG(loopback, tag)
                        assert_se(sd_device_monitor_filter_add_match_tag(monitor_client, tag) >= 0);

        if ((subsystem_filter || tag_filter) && use_bpf)
                assert_se(sd_device_monitor_filter_update(monitor_client) >= 0);

        r = device_monitor_send_device(monitor_server, monitor_client, loopback);
        if (r < 0)
                return log_error_errno(r, "Failed to send loopback device: %m");

        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 0);

        return 0;
}

static void test_subsystem_filter(void) {
        _cleanup_(sd_device_monitor_unrefp) sd_device_monitor *monitor_server = NULL, *monitor_client = NULL;
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        _cleanup_(sd_device_unrefp) sd_device *loopback = NULL;
        const char *syspath, *subsystem, *p, *s;
        sd_device *d;

        log_info("/* %s */", __func__);

        assert_se(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo") >= 0);
        assert_se(sd_device_get_syspath(loopback, &syspath) >= 0);
        assert_se(sd_device_get_subsystem(loopback, &subsystem) >= 0);
        assert_se(device_add_property(loopback, "ACTION", "add") >= 0);
        assert_se(device_add_property(loopback, "SEQNUM", "10") >= 0);

        assert_se(device_monitor_new_full(&monitor_server, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(sd_device_monitor_start(monitor_server, NULL, NULL, NULL) >= 0);

        assert_se(device_monitor_new_full(&monitor_client, MONITOR_GROUP_NONE, -1) >= 0);
        assert_se(device_monitor_allow_unicast_sender(monitor_client, monitor_server) >= 0);
        assert_se(sd_device_monitor_filter_add_match_subsystem_devtype(monitor_client, subsystem, NULL) >= 0);
        assert_se(sd_device_monitor_start(monitor_client, monitor_handler, (void *) syspath, "subsystem-filter") >= 0);

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_add_match_subsystem(e, subsystem, false) >= 0);
        FOREACH_DEVICE(e, d) {
                assert_se(sd_device_get_syspath(d, &p) >= 0);
                assert_se(sd_device_get_subsystem(d, &s) >= 0);

                log_info("Sending device subsystem:%s syspath:%s", s, p);
                assert_se(device_monitor_send_device(monitor_server, monitor_client, d) >= 0);
        }

        log_info("Sending device subsystem:%s syspath:%s", subsystem, syspath);
        assert_se(device_monitor_send_device(monitor_server, monitor_client, loopback) >= 0);
        assert_se(sd_event_loop(sd_device_monitor_get_event(monitor_client)) == 0);
}

int main(int argc, char *argv[]) {
        int r;

        test_setup_logging(LOG_INFO);

        if (getuid() != 0)
                return log_tests_skipped("not root");

        r = test_loopback(false, false, false);
        if (r < 0) {
                assert_se(r == -EPERM && detect_container() > 0);
                return log_tests_skipped("Running in container? Skipping remaining tests");
        }

        assert_se(test_loopback( true, false, false) >= 0);
        assert_se(test_loopback(false,  true, false) >= 0);
        assert_se(test_loopback( true,  true, false) >= 0);
        assert_se(test_loopback( true, false,  true) >= 0);
        assert_se(test_loopback(false,  true,  true) >= 0);
        assert_se(test_loopback( true,  true,  true) >= 0);

        test_subsystem_filter();

        return 0;
}
