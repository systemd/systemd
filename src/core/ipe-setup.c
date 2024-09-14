/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "copy.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "ipe-setup.h"
#include "path-util.h"

#define IPE_SECFS_DIR "/sys/kernel/security/ipe"
#define IPE_SECFS_NEW_POLICY IPE_SECFS_DIR "/new_policy"
#define IPE_SECFS_POLICIES IPE_SECFS_DIR "/policies/"
#define IPE_INPUT_POLICY_DIR "/etc/ipe"

int ipe_setup(void) {
#if ENABLE_IPE
        _cleanup_closedir_ DIR *policy_dir = NULL;
        int r;

        /* Very quick smoke tests first: this is in the citical, sequential boot path, and in most cases it
         * is unlikely this will be configured, so do the fastest existence checks first and immediately
         * return if there's nothing to do. */

        if (access(IPE_SECFS_DIR, F_OK) < 0) {
                log_debug_errno(errno, "IPE support is disabled in the kernel, ignoring: %m");
                return 0;
        }

        if (access(IPE_INPUT_POLICY_DIR, F_OK) < 0) {
                log_debug_errno(errno,
                                "No IPE custom policy directory %s, ignoring: %m",
                                IPE_INPUT_POLICY_DIR);
                return 0;
        }

        policy_dir = opendir(IPE_INPUT_POLICY_DIR);
        if (!policy_dir)
                return log_error_errno(
                                errno,
                                "Failed to open the IPE custom policy directory %s: %m",
                                IPE_INPUT_POLICY_DIR);

        FOREACH_DIRENT(de, policy_dir, return log_error_errno(errno, "Failed to read %s directory: %m", IPE_INPUT_POLICY_DIR)) {
                _cleanup_free_ char *policy_name = NULL, *output_path = NULL, *activate_path = NULL;
                _cleanup_close_ int input = -EBADF, output = -EBADF;
                const char *suffix;

                if (de->d_type != DT_REG)
                        continue;

                suffix = endswith(de->d_name, ".p7b");
                if (!suffix)
                        continue;

                policy_name = strndup(de->d_name, suffix - de->d_name);
                if (!policy_name)
                        return log_oom();

                input = openat(dirfd(policy_dir), de->d_name, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
                if (input < 0)
                        return log_error_errno(
                                        errno,
                                        "Failed to open the IPE custom policy file %s/%s: %m",
                                        IPE_INPUT_POLICY_DIR,
                                        de->d_name);

                /* If policy is already installed, try to update it */
                output_path = path_join(IPE_SECFS_POLICIES, policy_name, "update");
                if (!output_path)
                        return log_oom();

                output = open(output_path, O_WRONLY|O_CLOEXEC);
                if (output < 0 && errno == ENOENT)
                        /* Policy is not installed, install it and activate it */
                        output = open(IPE_SECFS_NEW_POLICY, O_WRONLY|O_CLOEXEC);
                if (output < 0)
                        return log_error_errno(
                                        errno,
                                        "Failed to open the IPE policy handle for writing: %m");

                /* The policy is inline signed in binary format, so it has to be copied in one go, otherwise the
                 * kernel will reject partial inputs with -EBADMSG. */
                r = copy_bytes(input, output, UINT64_MAX, /* copy_flags= */ 0);
                if (r < 0)
                        return log_error_errno(
                                        r,
                                        "Failed to copy the IPE policy %s/%s to %s: %m",
                                        IPE_INPUT_POLICY_DIR,
                                        de->d_name,
                                        output_path);

                activate_path = path_join(IPE_SECFS_POLICIES, policy_name, "active");
                if (!activate_path)
                        return log_oom();

                r = write_string_file(activate_path, "1", 0);
                if (r < 0 && r == -ESTALE) {
                        log_debug("IPE policy %s is already loaded with a version that is equal or higher, skipping.",
                                  policy_name);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to activate the IPE policy %s: %m", policy_name);

                log_info("Successfully loaded and activated the IPE policy %s.", policy_name);
        }

#endif /* ENABLE_IPE */
        return 0;
}
