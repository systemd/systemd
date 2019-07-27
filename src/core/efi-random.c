/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <linux/random.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chattr-util.h"
#include "efi-random.h"
#include "efivars.h"
#include "fd-util.h"
#include "fs-util.h"
#include "strv.h"

/* If a random seed was passed by the boot loader in the LoaderRandomSeed EFI variable, let's credit it to
 * the kernel's random pool, but only once per boot. If this is run very early during initialization we can
 * instantly boot up with a filled random pool.
 *
 * This makes no judgement on the entropy passed, it's the job of the boot loader to only pass us a seed that
 * is suitably validated. */

static void lock_down_efi_variables(void) {
        const char *p;
        int r;

        /* Paranoia: let's restrict access modes of these a bit, so that unprivileged users can't use them to
         * identify the system or gain too much insight into what we might have credited to the entropy
         * pool. */
        FOREACH_STRING(p,
                       "/sys/firmware/efi/efivars/LoaderRandomSeed-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f",
                       "/sys/firmware/efi/efivars/LoaderSystemToken-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f") {

                r = chattr_path(p, 0, FS_IMMUTABLE_FL, NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        log_warning_errno(r, "Failed to drop FS_IMMUTABLE_FL from %s, ignoring: %m", p);

                if (chmod(p, 0600) < 0)
                        log_warning_errno(errno, "Failed to reduce access mode of %s, ignoring: %m", p);
        }
}

int efi_take_random_seed(void) {
        _cleanup_free_ struct rand_pool_info *info = NULL;
        _cleanup_free_ void *value = NULL;
        _cleanup_close_ int random_fd = -1;
        size_t size;
        int r;

        /* Paranoia comes first. */
        lock_down_efi_variables();

        if (access("/run/systemd/efi-random-seed-taken", F_OK) < 0) {
                if (errno != ENOENT) {
                        log_warning_errno(errno, "Failed to determine whether we already used the random seed token, not using it.");
                        return 0;
                }

                /* ENOENT means we haven't used it yet. */
        } else {
                log_debug("EFI random seed already used, not using again.");
                return 0;
        }

        r = efi_get_variable(EFI_VENDOR_LOADER, "LoaderRandomSeed", NULL, &value, &size);
        if (r == -EOPNOTSUPP) {
                log_debug_errno(r, "System lacks EFI support, not initializing random seed from EFI variable.");
                return 0;
        }
        if (r == -ENOENT) {
                log_debug_errno(r, "Boot loader did not pass LoaderRandomSeed EFI variable, not crediting any entropy.");
                return 0;
        }
        if (r < 0)
                return log_warning_errno(r, "Failed to read LoaderRandomSeed EFI variable, ignoring: %m");

        if (size == 0)
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Random seed passed from boot loader has zero size? Ignoring.");

        /* The kernel API only accepts "int" as entropy count (which is in bits), let's avoid any chance for
         * confusion here. */
        if (size > INT_MAX / 8)
                size = INT_MAX / 8;

        random_fd = open("/dev/urandom", O_WRONLY|O_CLOEXEC|O_NOCTTY);
        if (random_fd < 0)
                return log_warning_errno(errno, "Failed to open /dev/urandom for writing, ignoring: %m");

        /* Before we use the seed, let's mark it as used, so that we never credit it twice. Also, it's a nice
         * way to let users known that we successfully acquired entropy from the boot laoder. */
        r = touch("/run/systemd/efi-random-seed-taken");
        if (r < 0)
                return log_warning_errno(r, "Unable to mark EFI random seed as used, not using it: %m");

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
