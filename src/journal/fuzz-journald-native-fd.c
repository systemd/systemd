/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "fd-util.h"
#include "fuzz.h"
#include "fuzz-journald-util.h"
#include "journald-native.h"
#include "memfd-util.h"
#include "process-util.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_close_ int sealed_fd = -EBADF, unsealed_fd = -EBADF;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-journald-native-fd.XXXXXX";
        char *label = NULL;
        size_t label_len = 0;
        struct ucred ucred;
        struct timeval *tv = NULL;

        fuzz_setup_logging();

        dummy_manager_new(&m, NULL, 0);

        sealed_fd = memfd_new_and_seal(NULL, data, size);
        assert_se(sealed_fd >= 0);
        ucred = (struct ucred) {
                .pid = getpid_cached(),
                .uid = geteuid(),
                .gid = getegid(),
        };
        (void) manager_process_native_file(m, sealed_fd, &ucred, tv, label, label_len);

        unsealed_fd = mkostemp_safe(name);
        assert_se(unsealed_fd >= 0);
        assert_se(write(unsealed_fd, data, size) == (ssize_t) size);
        assert_se(lseek(unsealed_fd, 0, SEEK_SET) == 0);
        (void) manager_process_native_file(m, unsealed_fd, &ucred, tv, label, label_len);

        return 0;
}
