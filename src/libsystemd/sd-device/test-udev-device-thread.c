/* SPDX-License-Identifier: LGPL-2.1+ */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "libudev.h"

#include "macro.h"
#include "tests.h"

static void* thread(void *p) {
        struct udev_enumerate **e = p;

        assert_se(!(*e = udev_enumerate_unref(*e)));

        return NULL;
}

int main(int argc, char *argv[]) {
        struct udev_list_entry *entry;
        struct udev_enumerate *e;
        bool has = false;
        pthread_t t;

        assert_se(unsetenv("SYSTEMD_MEMPOOL") == 0);

        test_setup_logging(LOG_INFO);

        assert_se(e = udev_enumerate_new(NULL));
        assert_se(udev_enumerate_add_match_is_initialized(e) >= 0);
        assert_se(udev_enumerate_scan_devices(e) >= 0);

        assert_se(entry = udev_enumerate_get_list_entry(e));
        for (; entry; entry = udev_list_entry_get_next(entry)) {
                struct udev_device *d;
                const char *syspath;

                assert_se(syspath = udev_list_entry_get_name(entry));
                assert_se(d = udev_device_new_from_syspath(NULL, syspath));
                if (udev_device_get_properties_list_entry(d)) {
                        log_debug("Device %s has some properties.", syspath);
                        has = true;
                        break;
                }
        }
        assert_se(has);

        assert_se(pthread_create(&t, NULL, thread, &e) == 0);
        assert_se(pthread_join(t, NULL) == 0);

        assert_se(!e);

        return 0;
}
