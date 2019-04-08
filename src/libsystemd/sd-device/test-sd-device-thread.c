/* SPDX-License-Identifier: LGPL-2.1+ */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "sd-device.h"

#include "device-util.h"
#include "macro.h"

static void* thread(void *p) {
        sd_device **d = p;

        assert_se(!(*d = sd_device_unref(*d)));

        return NULL;
}

int main(int argc, char *argv[]) {
        sd_device *loopback;
        pthread_t t;
        const char *key, *value;

        assert_se(unsetenv("SYSTEMD_MEMPOOL") == 0);

        assert_se(sd_device_new_from_syspath(&loopback, "/sys/class/net/lo") >= 0);

        FOREACH_DEVICE_PROPERTY(loopback, key, value)
                printf("%s=%s\n", key, value);

        assert_se(pthread_create(&t, NULL, thread, &loopback) == 0);
        assert_se(pthread_join(t, NULL) == 0);

        assert_se(!loopback);

        return 0;
}
