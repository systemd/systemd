/* SPDX-License-Identifier: LGPL-2.1+ */

#include "device-enumerator-private.h"
#include "device-private.h"
#include "device-util.h"
#include "string-util.h"
#include "tests.h"
#include "util.h"

static void test_sd_device_basic(void) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;

        assert_se(sd_device_enumerator_new(&e) >= 0);
        assert_se(sd_device_enumerator_allow_uninitialized(e) >= 0);
        FOREACH_DEVICE(e, d) {
                const char *syspath, *devpath, *subsystem, *val;
                dev_t devnum;
                usec_t usec;
                int i, r;

                assert_se(sd_device_get_syspath(d, &syspath) >= 0);

                r = sd_device_get_subsystem(d, &subsystem);
                assert_se(r >= 0 || r == -ENOENT);

                r = sd_device_get_devtype(d, &val);
                assert_se(r >= 0 || r == -ENOENT);

                r = sd_device_get_devnum(d, &devnum);
                assert_se(r >= 0 || r == -ENOENT);

                r = sd_device_get_ifindex(d, &i);
                assert_se(r >= 0 || r == -ENOENT);

                r = sd_device_get_driver(d, &val);
                assert_se(r >= 0 || r == -ENOENT);

                assert_se(sd_device_get_devpath(d, &devpath) >= 0);

                r = sd_device_get_devname(d, &val);
                assert_se(r >= 0 || r == -ENOENT);

                assert_se(sd_device_get_sysname(d, &val) >= 0);

                r = sd_device_get_sysnum(d, &val);
                assert_se(r >= 0 || r == -ENOENT);

                i = 0;
                assert_se(sd_device_get_is_initialized(d, &i) >= 0);
                if (i > 0) {
                        r = sd_device_get_usec_since_initialized(d, &usec);
                        assert_se(r >= 0 || r == -ENODATA);
                }

                r = sd_device_get_sysattr_value(d, "name_assign_type", &val);
                assert_se(r >= 0 || IN_SET(r, -ENOENT, -EINVAL));

                r = sd_device_get_property_value(d, "ID_NET_DRIVER", &val);
                assert_se(r >= 0 || r == -ENOENT);

                log_debug("syspath:%s devpath:%s subsystem:%s", syspath, devpath, strempty(subsystem));
        }
}

int main(int argc, char **argv) {
        test_setup_logging(LOG_INFO);

        test_sd_device_basic();
        return 0;
}
