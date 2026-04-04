/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald-util.h"
#include "journald-kmsg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free(manager) Manager *m = NULL;

        if (size == 0)
                return 0;

        fuzz_setup_logging();

        dummy_manager_new(&m, data, size);
        dev_kmsg_record(m, m->buffer, size);

        return 0;
}
