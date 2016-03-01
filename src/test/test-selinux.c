/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

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

#include <sys/stat.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "log.h"
#include "selinux-util.h"
#include "time-util.h"

static void test_testing(void) {
        bool b;

        log_info("============ %s ==========", __func__);

        b = mac_selinux_use();
        log_info("mac_selinux_use → %d", b);

        b = mac_selinux_have();
        log_info("mac_selinux_have → %d", b);

        mac_selinux_retest();

        b = mac_selinux_use();
        log_info("mac_selinux_use → %d", b);

        b = mac_selinux_have();
        log_info("mac_selinux_have → %d", b);
}

static void test_loading(void) {
        usec_t n1, n2;
        int r;

        log_info("============ %s ==========", __func__);

        n1 = now(CLOCK_MONOTONIC);
        r = mac_selinux_init();
        n2 = now(CLOCK_MONOTONIC);
        log_info_errno(r, "mac_selinux_init → %d (%m) %.2fs", r, (n2 - n1)/1e6);
}

static void test_cleanup(void) {
        usec_t n1, n2;

        log_info("============ %s ==========", __func__);

        n1 = now(CLOCK_MONOTONIC);
        mac_selinux_finish();
        n2 = now(CLOCK_MONOTONIC);
        log_info("mac_selinux_finish → %.2fs", (n2 - n1)/1e6);
}

static void test_misc(const char* fname) {
        _cleanup_(mac_selinux_freep) char *label = NULL, *label2 = NULL, *label3 = NULL;
        int r;
        _cleanup_close_ int fd = -1;

        log_info("============ %s ==========", __func__);

        r = mac_selinux_get_our_label(&label);
        log_info_errno(r, "mac_selinux_get_our_label → %d (%m), \"%s\"", r, label);

        r = mac_selinux_get_create_label_from_exe(fname, &label2);
        log_info_errno(r, "mac_selinux_create_label_from_exe → %d (%m), \"%s\"", r, label2);

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        assert_se(fd >= 0);

        r = mac_selinux_get_child_mls_label(fd, fname, label2, &label3);
        log_info_errno(r, "mac_selinux_get_child_mls_label → %d (%m), \"%s\"", r, label3);
}

static void test_create_file_prepare(const char* fname) {
        int r;

        log_info("============ %s ==========", __func__);

        r = mac_selinux_create_file_prepare(fname, S_IRWXU);
        log_info_errno(r, "mac_selinux_create_file_prepare → %d (%m)", r);

        mac_selinux_create_file_clear();
}

int main(int argc, char **argv) {
        const char *path = SYSTEMD_BINARY_PATH;
        if (argc >= 2)
                path = argv[1];

        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        test_testing();
        test_loading();
        test_misc(path);
        test_create_file_prepare(path);
        test_cleanup();

        return 0;
}
