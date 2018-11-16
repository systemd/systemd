/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fuzz.h"
#include "journald-kmsg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        Server s = {};
        _cleanup_free_ char *buffer = NULL;

        if (size == 0)
                return 0;

        s = (Server) {
                .syslog_fd = -1,
                .native_fd = -1,
                .stdout_fd = -1,
                .dev_kmsg_fd = -1,
                .audit_fd = -1,
                .hostname_fd = -1,
                .notify_fd = -1,
                .storage = STORAGE_NONE,
        };
        assert_se(sd_event_default(&s.event) >= 0);
        buffer = memdup(data, size);
        assert_se(buffer);
        dev_kmsg_record(&s, buffer, size);
        server_done(&s);

        return 0;
}
