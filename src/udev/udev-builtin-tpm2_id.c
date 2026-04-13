/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "device-util.h"
#include "string-util.h"
#include "tpm2-util.h"
#include "udev-builtin.h"

static int builtin_tpm2_id(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        int r;

        if (argc != 2 || !streq(argv[1], "identify"))
                return log_device_error_errno(
                                dev, SYNTHETIC_ERRNO(EINVAL), "%s: expected: identify", argv[0]);

        const char *dn;
        r = sd_device_get_devname(dev, &dn);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get device node for device: %m");

        _cleanup_(tpm2_context_unrefp) Tpm2Context *c = NULL;
        r = tpm2_context_new(dn, &c);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to open device node '%s': %m", dn);

        Tpm2VendorInfo info;
        r = tpm2_get_vendor_info(c, &info);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to acquire TPM2 vendor information: %m");

        if (!isempty(info.manufacturer)) {
                r = udev_builtin_add_property(event, "ID_TPM2_MANUFACTURER", info.manufacturer);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to set field: %m");
        }

        if (!isempty(info.vendor_string)) {
                r = udev_builtin_add_property(event, "ID_TPM2_VENDOR_STRING", info.vendor_string);
                if (r < 0)
                        return log_device_error_errno(dev, r, "Failed to set field: %m");
        }

        _cleanup_free_ char *m = NULL;
        r = tpm2_vendor_info_to_modalias(&info, &m);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to get modalias string for TPM2 device: %m");

        r = udev_builtin_add_property(event, "ID_TPM2_MODALIAS", m);
        if (r < 0)
                return log_device_error_errno(dev, r, "Failed to set field: %m");

        return 0;
}

const UdevBuiltin udev_builtin_tpm2_id = {
        .name = "tpm2_id",
        .cmd = builtin_tpm2_id,
        .help = "Identify TPM2 chips",
        .run_once = true,
};
