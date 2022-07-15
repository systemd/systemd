/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "bus-label.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *unescaped = NULL, *escaped = NULL;

        unescaped = bus_label_unescape_n((const char*)data, size);
        assert_se(unescaped != NULL);
        escaped = bus_label_escape(unescaped);
        assert_se(escaped != NULL);

        return 0;
}
