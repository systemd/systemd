/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootctl-reboot-to-firmware.h"
#include "efi-api.h"
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
                if (r == -EOPNOTSUPP) {
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
