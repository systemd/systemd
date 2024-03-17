/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootctl-reboot-to-firmware.h"
#include "efi-api.h"
#include "errno-util.h"
#include "parse-util.h"

int verb_reboot_to_firmware(int argc, char *argv[], void *userdata) {
        int r;

        if (argc < 2) {
                r = efi_get_reboot_to_firmware();
                if (r > 0) {
                        puts("active");
                        return 0; /* success */
                }
                if (r == 0) {
                        puts("supported");
                        return 1; /* recognizable error #1 */
                }
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                        puts("not supported");
                        return 2; /* recognizable error #2 */
                }

                log_error_errno(r, "Failed to query reboot-to-firmware state: %m");
                return 3; /* other kind of error */
        } else {
                r = parse_boolean(argv[1]);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse argument: %s", argv[1]);

                r = efi_set_reboot_to_firmware(r);
                if (r < 0)
                        return log_error_errno(r, "Failed to set reboot-to-firmware option: %m");

                return 0;
        }
}

int vl_method_set_reboot_to_firmware(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        static const JsonDispatch dispatch_table[] = {
                { "state", JSON_VARIANT_BOOLEAN, json_dispatch_boolean, 0, 0 },
                {}
        };
        bool b;
        int r;

        r = varlink_dispatch(link, parameters, dispatch_table, &b);
        if (r != 0)
                return r;

        r = efi_set_reboot_to_firmware(b);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return varlink_error(link, "io.systemd.BootControl.RebootToFirmwareNotSupported", NULL);
        if (r < 0)
                return r;

        return varlink_reply(link, NULL);
}

int vl_method_get_reboot_to_firmware(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        int r;

        if (json_variant_elements(parameters) > 0)
                return varlink_error_invalid_parameter(link, parameters);

        r = efi_get_reboot_to_firmware();
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return varlink_error(link, "io.systemd.BootControl.RebootToFirmwareNotSupported", NULL);
        if (r < 0)
                return r;

        return varlink_replyb(link, JSON_BUILD_OBJECT(JSON_BUILD_PAIR_BOOLEAN("state", r)));
}
