/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fuzz.h"
#include "keyring-setup-var.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ void *p = NULL;

        /* The stub refuses larger variables, cover a bit beyond the limit */
        if (outside_size_range(size, 0, 128*1024))
                return 0;

        fuzz_setup_logging();

        p = memdup(data, size);
        assert_se(p || size == 0);

        for (size_t offset = 0;;) {
                const char *name;
                const void *payload;
                size_t payload_size;

                if (keyring_setup_next_record(p, size, &offset, &name, &payload, &payload_size) != EFI_SUCCESS)
                        break;

                DO_NOT_OPTIMIZE(keyring_setup_credential_name_is_valid(name));
                DO_NOT_OPTIMIZE(((const uint8_t *) payload)[payload_size - 1]);
        }

        return 0;
}
