/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <getopt.h>
#include <libcryptsetup.h>

#include "build.h"
#include "cryptsetup-util.h"
#include "device-private.h"
#include "device-util.h"
#include "main-func.h"
#include "udev-util.h"

static const char *arg_device = NULL;

static int help(void) {
        printf("%s [OPTIONS...] [PATH]\n\n"
               "  -h --help     Show this help text\n"
               "     --version  Show package version\n",
               program_invocation_short_name);
        return 0;
}

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
                        return help();
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


static int print_attribute(const char* name, const char* devname) {
        _cleanup_(sd_device_unrefp) struct sd_device *dev = NULL;
        char const *syspath, *sysname;
        int r;

        r = sd_device_new_from_devname(&dev, devname);
        if (r < 0)
                return log_debug_errno(r, "Could not resolve device '%s': %m", devname);

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return log_debug_errno(r, "Could not resolve syspath for device '%s': %m", devname);

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return log_debug_errno(r, "Could not resolve sysname for device '%s': %m", devname);

        printf("CRYPT_%s=%s\n", name, syspath);
        printf("CRYPT_%s_SYSNAME=%s\n", name, sysname);
        return 0;
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_device_unrefp) struct sd_device *dev = NULL;
        _cleanup_(crypt_freep) struct crypt_device *cd = NULL;
        const char *devnode, *type, *device_name, *metadata_device_name;
        int r;

        (void) udev_parse_config();
        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        if (arg_device) {
                r = sd_device_new_from_path(&dev, arg_device);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device from path %s: %m", arg_device);
        } else {
                r = device_new_from_strv(&dev, environ);
                if (r < 0)
                        return log_error_errno(r, "Failed to get current device from environment: %m");
        }

        r = sd_device_get_devname(dev, &devnode);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to get device name: %m");

        r = crypt_init_by_name_and_header(&cd, devnode, NULL);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to open crypt device: %m");

        type = crypt_get_type(cd);
        if (type == NULL)
                return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EINVAL), "Device is not a cryptsetup device");
        printf("CRYPT_TYPE=%s\n", type);

        if (streq(type, CRYPT_VERITY)) {
                struct crypt_params_verity verity_params;
                r = crypt_get_verity_info(cd, &verity_params);
                if (r < 0)
                        return log_device_debug_errno(dev, r, "Failed to get integrity parameters: %m");
                if (verity_params.data_device) {
                        r = print_attribute("DATA_DEVICE", verity_params.data_device);
                        if (r < 0)
                                return r;
                }
                if (verity_params.hash_device) {
                        r = print_attribute("HASH_DEVICE", verity_params.hash_device);
                        if (r < 0)
                                return r;
                }
                if (verity_params.fec_device) {
                        r = print_attribute("FEC_DEVICE", verity_params.fec_device);
                        if (r < 0)
                                return r;
                }
        } else {
                device_name = crypt_get_device_name(cd);
                if (device_name) {
                        r = print_attribute("DEVICE", device_name);
                        if (r < 0)
                                return r;
                }
                metadata_device_name = crypt_get_metadata_device_name(cd);
                if (metadata_device_name) {
                        r = print_attribute("METADATA_DEVICE", metadata_device_name);
                        if (r < 0)
                                return r;
                }
        }


        return 0;
}

DEFINE_MAIN_FUNCTION(run);
