/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2012 Roberto Sassu - Politecnico di Torino, Italy
                                   TORSEC group — http://security.polito.it
***/

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "ima-setup.h"
#include "log.h"

#define IMA_SECFS_DIR "/sys/kernel/security/ima"
#define IMA_SECFS_POLICY IMA_SECFS_DIR "/policy"
#define IMA_POLICY_PATH "/etc/ima/ima-policy"

int ima_setup(void) {
#if ENABLE_IMA
        _cleanup_fclose_ FILE *input = NULL;
        _cleanup_close_ int imafd = -1;
        unsigned lineno = 0;
        int r;

        if (access(IMA_SECFS_DIR, F_OK) < 0) {
                log_debug_errno(errno, "IMA support is disabled in the kernel, ignoring: %m");
                return 0;
        }

        if (access(IMA_SECFS_POLICY, W_OK) < 0) {
                log_warning_errno(errno, "Another IMA custom policy has already been loaded, ignoring: %m");
                return 0;
        }

        if (access(IMA_POLICY_PATH, F_OK) < 0) {
                log_debug_errno(errno, "No IMA custom policy file "IMA_POLICY_PATH", ignoring: %m");
                return 0;
        }

        imafd = open(IMA_SECFS_POLICY, O_WRONLY|O_CLOEXEC);
        if (imafd < 0) {
                log_error_errno(errno, "Failed to open the IMA kernel interface "IMA_SECFS_POLICY", ignoring: %m");
                return 0;
        }

        /* attempt to write the name of the policy file into sysfs file */
        if (write(imafd, IMA_POLICY_PATH, STRLEN(IMA_POLICY_PATH)) > 0)
                goto done;

        /* fall back to copying the policy line-by-line */
        input = fopen(IMA_POLICY_PATH, "re");
        if (!input) {
                log_warning_errno(errno, "Failed to open the IMA custom policy file "IMA_POLICY_PATH", ignoring: %m");
                return 0;
        }

        safe_close(imafd);

        imafd = open(IMA_SECFS_POLICY, O_WRONLY|O_CLOEXEC);
        if (imafd < 0) {
                log_error_errno(errno, "Failed to open the IMA kernel interface "IMA_SECFS_POLICY", ignoring: %m");
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                size_t len;

                r = read_line(input, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read the IMA custom policy file "IMA_POLICY_PATH": %m");
                if (r == 0)
                        break;

                len = strlen(line);
                lineno++;

                if (len > 0 && write(imafd, line, len) < 0)
                        return log_error_errno(errno, "Failed to load the IMA custom policy file "IMA_POLICY_PATH"%u: %m",
                                               lineno);
        }

done:
        log_info("Successfully loaded the IMA custom policy "IMA_POLICY_PATH".");
#endif /* ENABLE_IMA */
        return 0;
}
