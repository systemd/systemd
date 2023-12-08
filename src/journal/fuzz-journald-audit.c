/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-audit.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(server_freep) Server *s = NULL;

        fuzz_setup_logging();

        assert_se(server_new(&s) >= 0);
        dummy_server_init(s, data, size);
        process_audit_string(s, 0, s->buffer, size);

        return 0;
}
