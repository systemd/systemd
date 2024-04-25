/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Identifies FIDO CTAP1 ("U2F")/CTAP2 security tokens based on the usage declared in their report
 * descriptor and outputs suitable environment variables.
 *
 * Inspired by Andrew Lutomirski's 'u2f-hidraw-policy.c'
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/hid.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "build.h"
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

static const char *arg_device = NULL;

static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                { "help",     no_argument, NULL, 'h' },
                { "version",  no_argument, NULL, 'v' },
                {}
        };
        int c;

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        printf("%s [OPTIONS...] SYSFS_PATH\n\n"
                               "  -h --help     Show this help text\n"
                               "     --version  Show package version\n",
                               program_invocation_short_name);
                        return 0;
                case 'v':
                        return version();
                case '?':
                        return -EINVAL;
                default:
                        assert_not_reached();
                }

        if (argc > 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Error: unexpected argument.");

        arg_device = argv[optind];
        return 1;
}

static int run(int argc, char **argv) {
        _cleanup_(sd_device_unrefp) struct sd_device *device = NULL;
        _cleanup_free_ char *desc_path = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct sd_device *hid_device;
        const char *sys_path;
        uint8_t desc[HID_MAX_DESCRIPTOR_SIZE];
        ssize_t desc_len;
        int r;

        (void) udev_parse_config();
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_device) {
                r = sd_device_new_from_syspath(&device, arg_device);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device from syspath %s: %m", arg_device);
        } else {
                r = device_new_from_strv(&device, environ);
                if (r < 0)
                        return log_error_errno(r, "Failed to get current device from environment: %m");
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

        fd = open(desc_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY);
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
