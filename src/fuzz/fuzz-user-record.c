/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "fuzz.h"
#include "user-record.h"

#include "sd-json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *str = NULL;
        unsigned line = 0;
        int r;

        if (outside_size_range(size, 0, 65536))
                return 0;

        assert_se(str = memdup_suffix0(data, size));
        assert_se(ur = user_record_new());

        fuzz_setup_logging();

        r = sd_json_parse(str, 0, &v, &line, /* reterr_column= */ NULL);
        if (r < 0) {
                (void) log_syntax(/* unit= */ NULL, LOG_DEBUG, "<stdin>", line, r, "JSON parse failure.");
                return 0;
        }

        r = user_record_load(ur, v, USER_RECORD_LOAD_FULL|USER_RECORD_PERMISSIVE);
        if (r >= 0) {
                /* We have a valid record, so let's excercise a couple more functions */
                _cleanup_(user_record_unrefp) UserRecord *cloned = NULL;
                (void) user_record_clone(ur, USER_RECORD_LOAD_FULL, &cloned);

                (void) user_record_test_blocked(ur);
                (void) user_record_test_password_change_required(ur);
                (void) user_record_can_authenticate(ur);
                (void) user_record_luks_discard(ur);
                (void) user_record_drop_caches(ur);
        }

        return 0;
}
