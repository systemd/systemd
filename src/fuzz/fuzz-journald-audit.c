/* SPDX-License-Identifier: LGPL-2.1+ */

#include "fuzz.h"
#include "journald-audit.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        Server s;
        _cleanup_free_ char *buffer = NULL;

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
        buffer = memdup_suffix0(data, size);
        assert_se(buffer);
        process_audit_string(&s, 0, buffer, size);
        server_done(&s);

        return 0;
}
