/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "fd-util.h"
#include "fs-util.h"
#include "fuzz.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "udev-rules.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-udev-rules.XXXXXX";
        int r;

        if (outside_size_range(size, 0, 65536))
                return 0;

        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        assert_se(fmkostemp_safe(filename, "r+", &f) == 0);
        if (size != 0)
                assert_se(fwrite(data, size, 1, f) == 1);
        fflush(f);

        assert_se(rules = udev_rules_new(RESOLVE_NAME_EARLY));
        r = udev_rules_parse_file(rules, filename);
        log_info_errno(r, "Parsing %s: %m", filename);
        assert_se(IN_SET(r,
                         0,       /* OK */
                         -ENOBUFS /* line length exceeded */));

        return 0;
}
