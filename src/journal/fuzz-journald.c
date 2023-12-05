/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fuzz-journald.h"
#include "journald-server.h"
#include "sd-event.h"

void dummy_server_init(Server *s, const uint8_t *buffer, size_t size) {
        assert(s);

        s->storage = STORAGE_NONE;
        assert_se(sd_event_default(&s->event) >= 0);

        if (buffer) {
                s->buffer = memdup_suffix0(buffer, size);
                assert_se(s->buffer);
        }
}

void fuzz_journald_processing_function(
                const uint8_t *data,
                size_t size,
                void (*f)(Server *s, const char *buf, size_t raw_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len)
        ) {

        _cleanup_(server_freep) Server *s = NULL;
        char *label = NULL;
        size_t label_len = 0;
        struct ucred *ucred = NULL;
        struct timeval *tv = NULL;

        if (size == 0)
                return;

        assert_se(server_new(&s) >= 0);
        dummy_server_init(s, data, size);
        (*f)(s, s->buffer, size, ucred, tv, label, label_len);
}
