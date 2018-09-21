/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "fuzz-journald.h"
#include "journald-server.h"
#include "sd-event.h"

void fuzz_journald_processing_function(
                const uint8_t *data,
                size_t size,
                void (*f)(Server *s, const char *buf, size_t raw_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len)
        ) {
        Server s = {};
        char *label = NULL;
        size_t label_len = 0;
        struct ucred *ucred = NULL;
        struct timeval *tv = NULL;

        if (size == 0)
                return;

        assert_se(sd_event_default(&s.event) >= 0);
        s.syslog_fd = s.native_fd = s.stdout_fd = s.dev_kmsg_fd = s.audit_fd = s.hostname_fd = s.notify_fd = -1;
        s.buffer = memdup_suffix0(data, size);
        assert_se(s.buffer);
        s.buffer_size = size + 1;
        s.storage = STORAGE_NONE;
        (*f)(&s, s.buffer, size, ucred, tv, label, label_len);
        server_done(&s);
}
