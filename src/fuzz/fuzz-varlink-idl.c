/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink-idl.h"

#include "alloc-util.h"
#include "fuzz.h"
#include "log.h"
#include "varlink-idl-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(sd_varlink_interface_freep) sd_varlink_interface *vi = NULL;
        _cleanup_free_ char *str = NULL, *dump = NULL;
        int r;

        if (outside_size_range(size, 0, 64 * 1024))
                return 0;

        fuzz_setup_logging();

        assert_se(str = memdup_suffix0(data, size));

        r = sd_varlink_idl_parse(str, /* reterr_line= */ NULL, /* reterr_column= */ NULL, &vi);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse varlink interface definition: %m");
                return 0;
        }

        assert_se(sd_varlink_idl_format(vi, &dump) >= 0);
        (void) varlink_idl_consistent(vi, LOG_DEBUG);

        return 0;
}
