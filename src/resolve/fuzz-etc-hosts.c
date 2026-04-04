/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fuzz.h"
#include "resolved-etc-hosts.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_clear(etc_hosts) EtcHosts h = {};

        fuzz_setup_logging();

        f = data_to_file(data, size);
        assert_se(f);

        (void) etc_hosts_parse(&h, f);

        return 0;
}
