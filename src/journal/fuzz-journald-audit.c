/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-audit.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *m = NULL;

        fuzz_setup_logging();

        assert_se(manager_new(&m, NULL) >= 0);
        dummy_manager_init(m, data, size);
        process_audit_string(m, 0, m->buffer, size);

        return 0;
}
