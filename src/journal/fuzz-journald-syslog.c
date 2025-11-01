/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald-util.h"
#include "journald-syslog.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        if (size == 0)
                return 0;

        _cleanup_(manager_freep) Manager *m = NULL;

        fuzz_setup_logging();

        dummy_manager_new(&m, data, size);
        manager_process_syslog_message(m, m->buffer, size, /* ucred = */ NULL, /* tv = */ NULL, /* label = */ NULL, /* label_len = */ 0, /* sa = */ NULL, /* salen = */ 0);

        return 0;
}
