/* SPDX-License-Identifier: LGPL-2.1+ */
/*
 * Identifies FIDO CTAP1 ("U2F")/CTAP2 security tokens based on the usage declared in their report
 * descriptor and outputs suitable environment variables.
 *
 * Inspired by Andrew Lutomirski's 'u2f-hidraw-policy.c'
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/hid.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "device-internal.h"
#include "device-private.h"
#include "device-util.h"
#include "fd-util.h"
#include "fido_id_desc.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "path-util.h"
#include "string-util.h"
#include "udev-util.h"

static int run(int argc, char **argv) {
        _cleanup_(sd_device_unrefp) struct sd_device *device = NULL;
        _cleanup_free_ char *desc_path = NULL;
        _cleanup_close_ int fd = -1;

        struct sd_device *hid_device;
        const char *sys_path;
        uint8_t desc[HID_MAX_DESCRIPTOR_SIZE];
        ssize_t desc_len;

        int r;

        log_set_target(LOG_TARGET_AUTO);
        udev_parse_config();
        log_parse_environment();
        log_open();

        if (argc > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Usage: hidraw_id [SYSFS_PATH]");

        if (argc == 1) {
                r = device_new_from_strv(&device, environ);
                if (r < 0)
                        return log_error_errno(r, "Failed to get current device from environment: %m");
        } else {
                r = sd_device_new_from_syspath(&device, argv[1]);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device from syspath: %m");
        }

        r = sd_device_get_parent(device, &hid_device);
        if (r < 0)
                return log_device_error_errno(device, r, "Failed to get parent HID device: %m");

        r = sd_device_get_syspath(hid_device, &sys_path);
        if (r < 0)
                return log_device_error_errno(hid_device, r, "Failed to get syspath for HID device: %m");

        desc_path = path_join(sys_path, "report_descriptor");
        if (!desc_path)
                return log_oom();

        fd = open(desc_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
                return log_device_error_errno(hid_device, errno,
                                              "Failed to open report descriptor at '%s': %m", desc_path);

        desc_len = read(fd, desc, sizeof(desc));
        if (desc_len < 0)
                return log_device_error_errno(hid_device, errno,
                                              "Failed to read report descriptor at '%s': %m", desc_path);
        if (desc_len == 0)
                return log_device_debug_errno(hid_device, SYNTHETIC_ERRNO(EINVAL),
                                              "Empty report descriptor at '%s'.", desc_path);

        r = is_fido_security_token_desc(desc, desc_len);
        if (r < 0)
                return log_device_debug_errno(hid_device, r,
                                              "Failed to parse report descriptor at '%s'.", desc_path);
        if (r > 0) {
                printf("ID_FIDO_TOKEN=1\n");
                printf("ID_SECURITY_TOKEN=1\n");
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
