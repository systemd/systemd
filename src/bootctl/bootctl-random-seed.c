/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "bootctl.h"
#include "bootctl-random-seed.h"
#include "bootctl-util.h"
#include "efivars.h"
#include "env-util.h"
#include "fd-util.h"
#include "find-esp.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "io-util.h"
#include "log.h"
#include "random-util.h"
#include "sha256.h"
#include "tmpfile-util.h"
#include "umask-util.h"

static int random_seed_verify_permissions(int fd, mode_t expected_type) {
        _cleanup_free_ char *full_path = NULL;
        struct stat st;
        int r;

        assert(fd >= 0);

        r = fd_get_path(fd, &full_path);
        if (r < 0)
                return log_error_errno(r, "Unable to determine full path of random seed fd: %m");

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Unable to stat %s: %m", full_path);

        if (((st.st_mode ^ expected_type) & S_IFMT) != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADF),
                                       "Unexpected inode type when validating random seed access mode on '%s'.", full_path);

        if ((st.st_mode & 0007) == 0) /* All world bits are off? Then all is good */
                return 0;

        if (S_ISREG(expected_type))
                log_error("%s%sRandom seed file '%s' is world accessible, which is a security hole!%s%s",
                          optional_glyph(GLYPH_WARNING_SIGN), optional_glyph(GLYPH_SPACE),
                          full_path,
                          optional_glyph(GLYPH_SPACE), optional_glyph(GLYPH_WARNING_SIGN));
        else
                log_error("%s%s Mount point '%s' which backs the random seed file is world accessible, which is a security hole! %s%s",
                          optional_glyph(GLYPH_WARNING_SIGN), optional_glyph(GLYPH_SPACE),
                          full_path,
                          optional_glyph(GLYPH_SPACE), optional_glyph(GLYPH_WARNING_SIGN));

        return 1;
}

static int set_system_token(void) {
        uint8_t buffer[RANDOM_EFI_SEED_SIZE];
        size_t token_size;
        int r;

        if (!touch_variables())
                return 0;

        r = secure_getenv_bool("SYSTEMD_WRITE_SYSTEM_TOKEN");
        if (r < 0) {
                if (r != -ENXIO)
                        log_warning_errno(r, "Failed to parse $SYSTEMD_WRITE_SYSTEM_TOKEN, ignoring.");
        } else if (r == 0) {
                log_notice("Not writing system token, because $SYSTEMD_WRITE_SYSTEM_TOKEN is set to false.");
                return 0;
        }

        r = efi_get_variable(EFI_LOADER_VARIABLE_STR("LoaderSystemToken"), NULL, NULL, &token_size);
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
                r = efi_set_variable(EFI_LOADER_VARIABLE_STR("LoaderSystemToken"), buffer, sizeof(buffer));
                if (r < 0) {
                        if (arg_graceful() == ARG_GRACEFUL_NO)
                                return log_error_errno(r, "Failed to write 'LoaderSystemToken' EFI variable: %m");

                        if (r == -EINVAL)
                                log_notice_errno(r, "Unable to write 'LoaderSystemToken' EFI variable (firmware problem?), ignoring: %m");
                        else
                                log_notice_errno(r, "Unable to write 'LoaderSystemToken' EFI variable, ignoring: %m");
                } else
                        log_info("Successfully initialized system token in EFI variable with %zu bytes.", sizeof(buffer));
        }

        return 0;
}

int install_random_seed(const char *esp) {
        _cleanup_close_ int esp_fd = -EBADF, loader_dir_fd = -EBADF, fd = -EBADF;
        _cleanup_free_ char *tmp = NULL;
        uint8_t buffer[RANDOM_EFI_SEED_SIZE];
        struct sha256_ctx hash_state;
        bool refreshed, warned = false;
        int r;

        assert(esp);

        assert_cc(RANDOM_EFI_SEED_SIZE == SHA256_DIGEST_SIZE);

        if (!arg_install_random_seed)
                return 0;

        esp_fd = open(esp, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        if (esp_fd < 0)
                return log_error_errno(errno, "Failed to open ESP directory '%s': %m", esp);

        (void) random_seed_verify_permissions(esp_fd, S_IFDIR);

        loader_dir_fd = open_mkdir_at(esp_fd, "loader", O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOFOLLOW, 0775);
        if (loader_dir_fd < 0)
                return log_error_errno(loader_dir_fd, "Failed to open loader directory '%s/loader': %m", esp);

        r = crypto_random_bytes(buffer, sizeof(buffer));
        if (r < 0)
                return log_error_errno(r, "Failed to acquire random seed: %m");

        sha256_init_ctx(&hash_state);
        sha256_process_bytes_and_size(buffer, sizeof(buffer), &hash_state);

        fd = openat(loader_dir_fd, "random-seed", O_NOFOLLOW|O_CLOEXEC|O_RDONLY|O_NOCTTY);
        if (fd < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open old random seed file: %m");

                sha256_process_bytes(&(const ssize_t) { 0 }, sizeof(ssize_t), &hash_state);
                refreshed = false;
        } else {
                ssize_t n;

                warned = random_seed_verify_permissions(fd, S_IFREG) > 0;

                /* Hash the old seed in so that we never regress in entropy. */

                n = read(fd, buffer, sizeof(buffer));
                if (n < 0)
                        return log_error_errno(errno, "Failed to read old random seed file: %m");

                sha256_process_bytes_and_size(buffer, n, &hash_state);

                fd = safe_close(fd);
                refreshed = n > 0;
        }

        sha256_finish_ctx(&hash_state, buffer);

        if (tempfn_random("random-seed", "bootctl", &tmp) < 0)
                return log_oom();

        fd = openat(loader_dir_fd, tmp, O_CREAT|O_EXCL|O_NOFOLLOW|O_NOCTTY|O_WRONLY|O_CLOEXEC, 0600);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open random seed file for writing: %m");

        if (!warned) /* only warn once per seed file */
                (void) random_seed_verify_permissions(fd, S_IFREG);

        r = loop_write(fd, buffer, sizeof(buffer));
        if (r < 0) {
                log_error_errno(r, "Failed to write random seed file: %m");
                goto fail;
        }

        if (fsync(fd) < 0 || fsync(loader_dir_fd) < 0) {
                r = log_error_errno(errno, "Failed to sync random seed file: %m");
                goto fail;
        }

        if (renameat(loader_dir_fd, tmp, loader_dir_fd, "random-seed") < 0) {
                r = log_error_errno(errno, "Failed to move random seed file into place: %m");
                goto fail;
        }

        tmp = mfree(tmp);

        if (syncfs(fd) < 0)
                return log_error_errno(errno, "Failed to sync ESP file system: %m");

        log_info("Random seed file %s/loader/random-seed successfully %s (%zu bytes).", esp, refreshed ? "refreshed" : "written", sizeof(buffer));

        return set_system_token();

fail:
        assert(tmp);
        (void) unlinkat(loader_dir_fd, tmp, 0);

        return r;
}

int verb_random_seed(int argc, char *argv[], void *userdata) {
        int r;

        r = find_esp_and_warn(arg_root, arg_esp_path, false, &arg_esp_path, NULL, NULL, NULL, NULL, NULL);
        if (r == -ENOKEY) {
                /* find_esp_and_warn() doesn't warn about ENOKEY, so let's do that on our own */
                if (arg_graceful() == ARG_GRACEFUL_NO)
                        return log_error_errno(r, "Unable to find ESP.");

                log_notice("No ESP found, not initializing random seed.");
                return 0;
        }
        if (r < 0)
                return r;

        r = install_random_seed(arg_esp_path);
        if (r < 0)
                return r;

        return 0;
}
