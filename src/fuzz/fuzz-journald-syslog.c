/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "fuzz.h"
#include "journald-server.h"
#include "journald-syslog.h"
#include "sd-event.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        Server s = {};
        char *label = NULL;
        size_t label_len = 0;
        struct ucred *ucred = NULL;
        struct timeval *tv = NULL;

        if (size == 0)
                return 0;

        assert_se(sd_event_default(&s.event) >= 0);
        s.syslog_fd = s.native_fd = s.stdout_fd = s.dev_kmsg_fd = s.audit_fd = s.hostname_fd = s.notify_fd = -1;
        s.buffer = memdup_suffix0(data, size);
        assert_se(s.buffer);
        s.buffer_size = size + 1;
        s.storage = STORAGE_NONE;
        server_process_syslog_message(&s, s.buffer, size, ucred, tv, label, label_len);
        server_done(&s);

        return 0;
}
