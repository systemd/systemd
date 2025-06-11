/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "fuzz-journald.h"
#include "journald-manager.h"

void dummy_manager_init(Manager *m, const uint8_t *buffer, size_t size) {
        assert(m);

        m->config.storage = STORAGE_NONE;
        assert_se(sd_event_default(&m->event) >= 0);

        if (buffer) {
                m->buffer = memdup_suffix0(buffer, size);
                assert_se(m->buffer);
        }
}

void fuzz_journald_processing_function(
                const uint8_t *data,
                size_t size,
                void (*f)(Manager *m, const char *buf, size_t raw_len, const struct ucred *ucred, const struct timeval *tv, const char *label, size_t label_len)
        ) {

        _cleanup_(manager_freep) Manager *m = NULL;
        char *label = NULL;
        size_t label_len = 0;
        struct ucred *ucred = NULL;
        struct timeval *tv = NULL;

        if (size == 0)
                return;

        assert_se(manager_new(&m, NULL) >= 0);
        dummy_manager_init(m, data, size);
        (*f)(m, m->buffer, size, ucred, tv, label, label_len);
}
