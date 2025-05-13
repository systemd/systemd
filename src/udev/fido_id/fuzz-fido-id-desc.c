/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/hid.h>

#include "fido_id_desc.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        fuzz_setup_logging();

        if (outside_size_range(size, 0, HID_MAX_DESCRIPTOR_SIZE))
                return 0;

        (void) is_fido_security_token_desc(data, size);

        return 0;
}
