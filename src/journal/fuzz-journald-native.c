/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-native.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        fuzz_journald_processing_function(data, size, server_process_native_message);
        return 0;
}
