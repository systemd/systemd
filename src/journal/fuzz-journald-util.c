/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "fuzz-journald-util.h"
#include "journald-manager.h"
#include "tests.h"

void dummy_manager_new(Manager **ret, const uint8_t *buffer, size_t size) {
        _cleanup_(manager_freep) Manager *m = NULL;

        assert(ret);

        ASSERT_OK(manager_new(&m));
        manager_merge_configs(m);
        m->config.storage = STORAGE_NONE;
        ASSERT_OK(sd_event_default(&m->event));

        if (buffer)
                ASSERT_NOT_NULL(m->buffer = memdup_suffix0(buffer, size));

        *ret = TAKE_PTR(m);
}

void fuzz_journald_processing_function(
                const uint8_t *data,
                size_t size,
                journal_process_t f) {

        if (size == 0)
                return;

        _cleanup_(manager_freep) Manager *m = NULL;
        dummy_manager_new(&m, data, size);
        f(m, m->buffer, size, /* ucred = */ NULL, /* tv = */ NULL, /* label = */ NULL, /* label_len = */ 0);
}
