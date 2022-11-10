/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chattr-util.h"
#include "efi-random.h"
#include "efivars.h"
#include "fd-util.h"
#include "fs-util.h"
#include "random-util.h"
#include "strv.h"

void lock_down_efi_variables(void) {
        const char *path = EFIVAR_PATH(EFI_LOADER_VARIABLE(LoaderSystemToken));
        int r;

        /* Paranoia: let's restrict access modes of these a bit, so that unprivileged users can't use them to
         * identify the system or gain too much insight into what we might have credited to the entropy
         * pool. */
        r = chattr_path(EFIVAR_PATH(EFI_LOADER_VARIABLE(LoaderSystemToken)), 0, FS_IMMUTABLE_FL, NULL);
        if (r == -ENOENT)
                return;
        if (r < 0)
                log_warning_errno(r, "Failed to drop FS_IMMUTABLE_FL from %s, ignoring: %m", path);

        if (chmod(path, 0600) < 0)
                log_warning_errno(errno, "Failed to reduce access mode of %s, ignoring: %m", path);
}
