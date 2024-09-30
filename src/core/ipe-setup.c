/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-files.h"
#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "ipe-setup.h"
#include "nulstr-util.h"
#include "path-util.h"

#define IPE_SECFS_DIR "/sys/kernel/security/ipe"
#define IPE_SECFS_NEW_POLICY IPE_SECFS_DIR "/new_policy"
#define IPE_SECFS_POLICIES IPE_SECFS_DIR "/policies/"

int ipe_setup(void) {
#if ENABLE_IPE
        _cleanup_strv_free_ char **policies = NULL;
        int r;

        /* Very quick smoke tests first: this is in the citical, sequential boot path, and in most cases it
         * is unlikely this will be configured, so do the fastest existence checks first and immediately
         * return if there's nothing to do. */

        if (access(IPE_SECFS_DIR, F_OK) < 0) {
                log_debug_errno(errno, "IPE support is disabled in the kernel, ignoring: %m");
                return 0;
        }

        r = conf_files_list_nulstr(
                        &policies,
                        ".p7b",
                        /* root= */ NULL,
                        CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED,
                        CONF_PATHS_NULSTR("ipe"));
        if (r < 0)
                return log_error_errno(r, "Failed to assemble list of IPE policies: %m");

        STRV_FOREACH(policy, policies) {
                _cleanup_free_ char *policy_name = NULL, *file_name = NULL, *output_path = NULL, *activate_path = NULL;
                _cleanup_close_ int input = -EBADF, output = -EBADF;
                const char *suffix;

                r = path_extract_filename(*policy, &file_name);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from IPE policy path %s: %m", *policy);

                /* Filtered by conf_files_list_nulstr() */
                suffix = ASSERT_PTR(endswith(file_name, ".p7b"));

                policy_name = strndup(file_name, suffix - file_name);
                if (!policy_name)
                        return log_oom();

                if (!filename_is_valid(policy_name))
                        return log_error_errno(
                                        SYNTHETIC_ERRNO(EINVAL),
                                        "Invalid IPE policy name %s",
                                        policy_name);

                input = open(*policy, O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
                if (input < 0)
                        return log_error_errno(
                                        errno,
                                        "Failed to open the IPE policy file %s: %m",
                                        *policy);

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
                                        "Failed to copy the IPE policy %s to %s: %m",
                                        *policy,
                                        output_path);

                output = safe_close(output);

                activate_path = path_join(IPE_SECFS_POLICIES, policy_name, "active");
                if (!activate_path)
                        return log_oom();

                r = write_string_file(activate_path, "1", WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r == -ESTALE) {
                        log_debug_errno(r,
                                        "IPE policy %s is already loaded with a version that is equal or higher, skipping.",
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
