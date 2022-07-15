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
        Server s;
        _cleanup_close_ int sealed_fd = -1, unsealed_fd = -1;
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-journald-native-fd.XXXXXX";
        char *label = NULL;
        size_t label_len = 0;
        struct ucred ucred;
        struct timeval *tv = NULL;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        dummy_server_init(&s, NULL, 0);

        sealed_fd = memfd_new(NULL);
        assert_se(sealed_fd >= 0);
        assert_se(write(sealed_fd, data, size) == (ssize_t) size);
        assert_se(memfd_set_sealed(sealed_fd) >= 0);
        assert_se(lseek(sealed_fd, 0, SEEK_SET) == 0);
        ucred = (struct ucred) {
                .pid = getpid_cached(),
                .uid = geteuid(),
                .gid = getegid(),
        };
        server_process_native_file(&s, sealed_fd, &ucred, tv, label, label_len);

        unsealed_fd = mkostemp_safe(name);
        assert_se(unsealed_fd >= 0);
        assert_se(write(unsealed_fd, data, size) == (ssize_t) size);
        assert_se(lseek(unsealed_fd, 0, SEEK_SET) == 0);
        server_process_native_file(&s, unsealed_fd, &ucred, tv, label, label_len);

        server_done(&s);

        return 0;
}
