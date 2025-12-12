/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald-util.h"
#include "journald-audit.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *m = NULL;

        fuzz_setup_logging();

        dummy_manager_new(&m, data, size);
        process_audit_string(m, 0, m->buffer, size);

        return 0;
}
