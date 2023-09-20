/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "vmspawn-settings.h"
#include "macro.h"
#include "string-util-fundamental.h"

int parse_config_feature(const char *s, ConfigFeature *ret) {
        assert(s);
        assert(ret);

        if (strcaseeq(s, "auto"))
                *ret = CONFIG_FEATURE_AUTO;
        else if (strcaseeq(s, "enabled"))
                *ret = CONFIG_FEATURE_ENABLED;
        else if (strcaseeq(s, "disabled"))
                *ret = CONFIG_FEATURE_DISABLED;
        else
                return -EINVAL;

        return 0;
}

int parse_qemu_firmware(const char *s, QemuFirmware *ret) {
        assert(s);
        assert(ret);

        if (strcaseeq(s, "direct"))
                *ret = QEMU_FIRMWARE_DIRECT;
        else if (strcaseeq(s, "uefi"))
                *ret = QEMU_FIRMWARE_UEFI;
        else if (strcaseeq(s, "bios"))
                *ret = QEMU_FIRMWARE_BIOS;
        else
                return -EINVAL;

        return 0;
}
