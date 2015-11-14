/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Michal Sekletar

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "boot-util.h"
#include "efivars.h"
#include "escape.h"
#include "fd-util.h"
#include "path-util.h"
#include "string-util.h"
#include "util.h"

static const char * const varname = "LoaderAttemptsPath";

int main(void) {
        int r;
        sd_id128_t uuid = {}, loader_part_uuid = {};
        _cleanup_free_ char *attempts_efi_path = NULL, *esp_path = NULL;
        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
        char *attempts_path;

        r = efi_get_variable_string(EFI_VENDOR_LOADER, varname, &attempts_efi_path);
        if (r == -ENOENT)
                return EXIT_SUCCESS;
        else if (r < 0) {
                        log_error_errno(r, "Failed to read EFI variable %s: %m", varname);
                        return EXIT_FAILURE;
        }

        efi_tilt_backslashes(attempts_efi_path);

        r = efi_loader_get_device_part_uuid(&loader_part_uuid);
        if (r < 0 && r == -ENOENT) {
                log_error_errno(r, "Failed to read EFI variable LoaderDevicePartUUID: %m");
                return EXIT_FAILURE;
        }

        proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
        if (!proc_self_mountinfo) {
                log_error_errno(errno, "Failed to open /proc/self/mountinfo: %m");
                return EXIT_FAILURE;
        }

        for (;;) {
                 _cleanup_free_ char *p = NULL, *q = NULL;

                r = fscanf(proc_self_mountinfo,
                           "%*s "       /* (1) mount id */
                           "%*s "       /* (2) parent id */
                           "%*s "       /* (3) major:minor */
                           "%*s "       /* (4) root */
                           "%ms "       /* (5) mount point */
                           "%*s"        /* (6) mount options */
                           "%*[^-]"     /* (7) optional fields */
                           "- "         /* (8) separator */
                           "%*s "       /* (9) file system type */
                           "%*s"        /* (10) mount source */
                           "%*s"        /* (11) mount options 2 */
                           "%*[^\n]",   /* some rubbish at the end */
                           &p);
                if (r != 1) {
                        if (r == EOF)
                                break;

                        continue;
                }

                r = cunescape(p, UNESCAPE_RELAX, &q);
                if (r < 0)
                        return r;

                r = esp_verify_fs_type(q);
                if (r < 0)
                        continue;

                r = esp_verify_path_is_esp_root(q);
                if (r < 0)
                        continue;

                r = esp_verify_partition(q, NULL, NULL, NULL, &uuid);
                if (r < 0)
                        continue;

                if (sd_id128_equal(uuid, loader_part_uuid)) {
                        esp_path = strdup(q);
                        if (!q) {
                                log_oom();
                                return EXIT_FAILURE;
                        }
                        break;
                }
        }

        attempts_path = strjoina(esp_path, attempts_efi_path);
        path_kill_slashes(attempts_path);

        (void) unlink(attempts_path);

        return 0;
}
