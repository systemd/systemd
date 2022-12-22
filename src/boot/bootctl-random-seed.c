/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bootctl.h"
#include "bootctl-random-seed.h"
#include "bootctl-util.h"
#include "efi-api.h"
#include "env-util.h"
#include "fd-util.h"
#include "find-esp.h"
#include "fs-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "random-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"

int install_random_seed(const char *esp) {
        _cleanup_(unlink_and_freep) char *tmp = NULL;
        uint8_t buffer[RANDOM_EFI_SEED_SIZE];
        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        size_t token_size;
        ssize_t n;
        int r;

        assert(esp);

        path = path_join(esp, "/loader/random-seed");
        if (!path)
                return log_oom();

        r = crypto_random_bytes(buffer, sizeof(buffer));
        if (r < 0)
                return log_error_errno(r, "Failed to acquire random seed: %m");

        /* Normally create_subdirs() should already have created everything we need, but in case "bootctl
         * random-seed" is called we want to just create the minimum we need for it, and not the full
         * list. */
        r = mkdir_parents(path, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create parent directory for %s: %m", path);

        r = tempfn_random(path, "bootctl", &tmp);
        if (r < 0)
                return log_oom();

        fd = open(tmp, O_CREAT|O_EXCL|O_NOFOLLOW|O_NOCTTY|O_WRONLY|O_CLOEXEC, 0600);
        if (fd < 0) {
                tmp = mfree(tmp);
                return log_error_errno(fd, "Failed to open random seed file for writing: %m");
        }

        n = write(fd, buffer, sizeof(buffer));
        if (n < 0)
                return log_error_errno(errno, "Failed to write random seed file: %m");
        if ((size_t) n != sizeof(buffer))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write while writing random seed file.");

        if (rename(tmp, path) < 0)
                return log_error_errno(r, "Failed to move random seed file into place: %m");

        tmp = mfree(tmp);

        log_info("Random seed file %s successfully written (%zu bytes).", path, sizeof(buffer));

        if (!arg_touch_variables)
                return 0;

        if (arg_root) {
                log_warning("Acting on %s, skipping EFI variable setup.",
                             arg_image ? "image" : "root directory");
                return 0;
        }

        if (!is_efi_boot()) {
                log_notice("Not booted with EFI, skipping EFI variable setup.");
                return 0;
        }

        r = getenv_bool("SYSTEMD_WRITE_SYSTEM_TOKEN");
        if (r < 0) {
                if (r != -ENXIO)
                         log_warning_errno(r, "Failed to parse $SYSTEMD_WRITE_SYSTEM_TOKEN, ignoring.");
        } else if (r == 0) {
                log_notice("Not writing system token, because $SYSTEMD_WRITE_SYSTEM_TOKEN is set to false.");
                return 0;
        }

        r = efi_get_variable(EFI_LOADER_VARIABLE(LoaderSystemToken), NULL, NULL, &token_size);
        if (r == -ENODATA)
                log_debug_errno(r, "LoaderSystemToken EFI variable is invalid (too short?), replacing.");
        else if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to test system token validity: %m");
        } else {
                if (token_size >= sizeof(buffer)) {
                        /* Let's avoid writes if we can, and initialize this only once. */
                        log_debug("System token already written, not updating.");
                        return 0;
                }

                log_debug("Existing system token size (%zu) does not match our expectations (%zu), replacing.", token_size, sizeof(buffer));
        }

        r = crypto_random_bytes(buffer, sizeof(buffer));
        if (r < 0)
                return log_error_errno(r, "Failed to acquire random seed: %m");

        /* Let's write this variable with an umask in effect, so that unprivileged users can't see the token
         * and possibly get identification information or too much insight into the kernel's entropy pool
         * state. */
        WITH_UMASK(0077) {
                r = efi_set_variable(EFI_LOADER_VARIABLE(LoaderSystemToken), buffer, sizeof(buffer));
                if (r < 0) {
                        if (!arg_graceful)
                                return log_error_errno(r, "Failed to write 'LoaderSystemToken' EFI variable: %m");

                        if (r == -EINVAL)
                                log_warning_errno(r, "Unable to write 'LoaderSystemToken' EFI variable (firmware problem?), ignoring: %m");
                        else
                                log_warning_errno(r, "Unable to write 'LoaderSystemToken' EFI variable, ignoring: %m");
                } else
                        log_info("Successfully initialized system token in EFI variable with %zu bytes.", sizeof(buffer));
        }

        return 0;
}

int verb_random_seed(int argc, char *argv[], void *userdata) {
        int r;

        r = find_esp_and_warn(arg_root, arg_esp_path, false, &arg_esp_path, NULL, NULL, NULL, NULL, NULL, NULL);
        if (r == -ENOKEY) {
                /* find_esp_and_warn() doesn't warn about ENOKEY, so let's do that on our own */
                if (!arg_graceful)
                        return log_error_errno(r, "Unable to find ESP.");

                log_notice("No ESP found, not initializing random seed.");
                return 0;
        }
        if (r < 0)
                return r;

        r = install_random_seed(arg_esp_path);
        if (r < 0)
                return r;

        (void) sync_everything();
        return 0;
}
