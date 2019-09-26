/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <linux/random.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chattr-util.h"
#include "dt-random.h"
#include "fd-util.h"
#include "fs-util.h"
#include "strv.h"
#include "hexdecoct.h"

int dt_take_random_seed(void) {
        _cleanup_free_ struct rand_pool_info *info = NULL;
        _cleanup_free_ void *value = NULL;
        _cleanup_close_ int random_fd = -1;
        _cleanup_close_ int var_fd = -1;
        char var_buf[680]; /* base64 max size is (n/3)*4, and we want a seed of 512 */
        size_t size;
        int r;

        if (access("/run/systemd/dt-random-seed-taken", F_OK) < 0) {
                if (errno != ENOENT) {
                        log_warning_errno(errno, "Failed to determine whether we already used the random seed token, not using it.");
                        return 0;
                }

                /* ENOENT means we haven't used it yet. */
        } else {
                log_debug("Device tree random seed already used, not using again.");
                return 0;
        }

        if (access("/sys/firmware/devicetree/base/chosen", F_OK) < 0) {
                log_debug_errno(errno, "System lacks device tree support, not initializing random seed from device tree variable.");
                return 0;
        }
        var_fd = open("/sys/firmware/devicetree/base/chosen/systemd,random-seed", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (var_fd < 0)
                return log_warning_errno(errno, "Failed to open /chosen/systemd,random-seed device tree node, ignoring: %m");
        r = read(var_fd, var_buf, sizeof(var_buf));
        if (r < 0)
                return log_warning_errno(errno, "Failed to read /chosen/systemd,random-seed device tree node, ignoring: %m");
        r = unbase64mem(var_buf, (size_t) r, &value, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to decode base 64 /chosen/systemd,random-seed device tree variable, ignoring: %m");

        /* The kernel API only accepts "int" as entropy count (which is in bits), let's avoid any chance for
         * confusion here. */
        if (size > INT_MAX / 8)
                size = INT_MAX / 8;

        random_fd = open("/dev/urandom", O_WRONLY|O_CLOEXEC|O_NOCTTY);
        if (random_fd < 0)
                return log_warning_errno(errno, "Failed to open /dev/urandom for writing, ignoring: %m");

        /* Before we use the seed, let's mark it as used, so that we never credit it twice. Also, it's a nice
         * way to let users known that we successfully acquired entropy from the boot laoder. */
        r = touch("/run/systemd/dt-random-seed-taken");
        if (r < 0)
                return log_warning_errno(r, "Unable to mark device tree random seed as used, not using it: %m");

        info = malloc(offsetof(struct rand_pool_info, buf) + size);
        if (!info)
                return log_oom();

        info->entropy_count = size * 8;
        info->buf_size = size;
        memcpy(info->buf, value, size);

        if (ioctl(random_fd, RNDADDENTROPY, info) < 0)
                return log_warning_errno(errno, "Failed to credit entropy, ignoring: %m");

        log_info("Successfully credited entropy passed from boot loader.");
        return 1;
}
