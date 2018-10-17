/* SPDX-License-Identifier: LGPL-2.1+ */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-device.h"

#include "device-util.h"
#include "macro.h"
#include "tests.h"

static void* thread(void *p) {
        sd_device_enumerator **e = p;

        assert_se(!(*e = sd_device_enumerator_unref(*e)));

        return NULL;
}

int main(int argc, char *argv[]) {
        sd_device_enumerator *e;
        bool has = false;
        sd_device *d;
        pthread_t t;

        assert_se(unsetenv("SYSTEMD_MEMPOOL") == 0);

        test_setup_logging(LOG_INFO);

        assert_se(sd_device_enumerator_new(&e) >= 0);

        FOREACH_DEVICE(e, d) {
                const char *key, *value, *syspath;

                FOREACH_DEVICE_PROPERTY(d, key, value) {
                        log_debug("%s=%s", key, value);
                        has = true;
                }

                if (has) {
                        assert_se(sd_device_get_syspath(d, &syspath) >= 0);
                        log_debug("Device %s has some properties.", syspath);
                        break;
                }
        }
        assert_se(has);

        assert_se(pthread_create(&t, NULL, thread, &e) == 0);
        assert_se(pthread_join(t, NULL) == 0);

        assert_se(!e);

        return 0;
}
