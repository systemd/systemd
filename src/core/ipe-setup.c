/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "copy.h"
#include "fd-util.h"
#include "fileio.h"
#include "ipe-setup.h"
#include "path-util.h"

#define IPE_SECFS_DIR "/sys/kernel/security/ipe"
#define IPE_SECFS_NEW_POLICY IPE_SECFS_DIR "/new_policy"
#define IPE_SECFS_POLICIES IPE_SECFS_DIR "/policies/"
#define IPE_POLICY_PATH "/etc/ipe/ipe-policy.p7b"

int ipe_setup(void) {
#if ENABLE_IPE
        _cleanup_free_ char *policy_name = NULL, *policy_version = NULL, *policy_existing_version = NULL,
                *policy_existing_version_file = NULL, *policy_activate = NULL, *output_path_free = NULL;
        _cleanup_fclose_ FILE *finput = NULL;
        _cleanup_close_ int input = -EBADF, output = -EBADF;
        const char *output_path;
        int r;

        if (access(IPE_SECFS_DIR, F_OK) < 0) {
                log_debug_errno(errno, "IPE support is disabled in the kernel, ignoring: %m");
                return 0;
        }

        if (access(IPE_POLICY_PATH, F_OK) < 0) {
                log_debug_errno(errno, "No IPE custom policy file "IPE_POLICY_PATH", ignoring: %m");
                return 0;
        }

        input = open(IPE_POLICY_PATH, O_RDONLY|O_CLOEXEC);
        if (input < 0)
                return log_error_errno(errno, "Failed to open the IPE custom policy file "IPE_POLICY_PATH", ignoring: %m");

        r = fdopen_independent(input, "re", &finput);
        if (r < 0)
                return log_error_errno(r, "Failed to fdopen the IPE custom policy file "IPE_POLICY_PATH", ignoring: %m");

        /* First we need to parse the policy name, since in order to activate it we need to know it, as it
         * will show up as a directory under /sys/kernel/security/ipe/policies/ and there will be an
         * 'active' file under it to write into, which will make it active. */
        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *p;

                r = read_line(finput, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read the IPE policy "IPE_POLICY_PATH": %m");
                if (r == 0)
                        break;

                p = strstrafter(line, "policy_name=");
                if (p && !policy_name) {
                        policy_name = strdup(p);
                        if (!policy_name)
                                return log_oom();
                        p = strchr(policy_name, ' ');
                        if (p)
                                *p = '\0';
                }

                p = strstrafter(line, "policy_version=");
                if (p && !policy_version) {
                        policy_version = strdup(p);
                        if (!policy_version)
                                return log_oom();
                        p = strchr(policy_version, ' ');
                        if (p)
                                *p = '\0';
                }

                if (policy_name && policy_version)
                        break;
        }

        if (!policy_name || !policy_version)
                return log_error_errno(ENOENT, "Failed to find policy_name= and policy_version= in the IPE policy "IPE_POLICY_PATH);

        policy_existing_version_file = path_join(IPE_SECFS_POLICIES, policy_name, "version");
        if (!policy_existing_version_file)
                return log_oom();

        r = read_virtual_file(policy_existing_version_file, SIZE_MAX, &policy_existing_version, /* ret_size= */ NULL);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read the existing IPE policy version: %m");
        if (r >= 0) {
                if (strverscmp_improved(policy_version, policy_existing_version) <= 0) {
                        log_info("The existing IPE policy '%s' is at version '%s', the new version is '%s', skipping.",
                                 policy_name,
                                 policy_existing_version,
                                 policy_version);
                        return 0;
                }

                /* Policy is already installed and older, update it */
                output_path_free = path_join(IPE_SECFS_POLICIES, policy_name, "update");
                if (!output_path_free)
                        return log_oom();
                output_path = output_path_free;
        } else
                /* Policy is not installed, install it and activate it */
                output_path = IPE_SECFS_NEW_POLICY;

        output = open(output_path, O_WRONLY|O_CLOEXEC);
        if (output < 0)
                return log_error_errno(errno, "Failed to open the IPE kernel interface %s, ignoring: %m", output_path);

        /* The policy is inline signed in binary format, so it has to be copied in one go, otherwise the
         * kernel will reject partial inputs with -EBADMSG. */
        r = copy_bytes(input, output, UINT64_MAX, /* copy_flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to copy the IPE policy "IPE_POLICY_PATH" to "IPE_SECFS_NEW_POLICY": %m");

        policy_activate = path_join(IPE_SECFS_POLICIES, policy_name, "active");
        if (!policy_activate)
                return log_oom();

        r = write_string_file(policy_activate, "1", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to activate the IPE custom policy "IPE_POLICY_PATH": %m");

        log_info("Successfully loaded the IPE custom policy "IPE_POLICY_PATH".");
#endif /* ENABLE_IPE */
        return 0;
}
