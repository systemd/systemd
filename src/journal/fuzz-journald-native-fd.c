/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fs-util.h"
#include "fuzz-journald.h"
#include "fuzz.h"
#include "journald-native.h"
#include "memfd-util.h"
#include "process-util.h"
#include "tmpfile-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(server_freep) Server *s = NULL;
        _cleanup_close_ int sealed_fd = -EBADF, unsealed_fd = -EBADF;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-journald-native-fd.XXXXXX";
        char *label = NULL;
        size_t label_len = 0;
        struct ucred ucred;
        struct timeval *tv = NULL;

        fuzz_setup_logging();

        assert_se(server_new(&s) >= 0);
        dummy_server_init(s, NULL, 0);

        sealed_fd = memfd_new_and_seal(NULL, data, size);
        assert_se(sealed_fd >= 0);
        ucred = (struct ucred) {
                .pid = getpid_cached(),
                .uid = geteuid(),
                .gid = getegid(),
        };
        server_process_native_file(s, sealed_fd, &ucred, tv, label, label_len);

        unsealed_fd = mkostemp_safe(name);
        assert_se(unsealed_fd >= 0);
        assert_se(write(unsealed_fd, data, size) == (ssize_t) size);
        assert_se(lseek(unsealed_fd, 0, SEEK_SET) == 0);
        server_process_native_file(s, unsealed_fd, &ucred, tv, label, label_len);

        return 0;
}
