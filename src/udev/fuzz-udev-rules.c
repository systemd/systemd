/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "conf-files.h"
#include "fd-util.h"
#include "fuzz.h"
#include "tests.h"
#include "tmpfile-util.h"
#include "udev-rules.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(udev_rules_freep) UdevRules *rules = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_tempfilep) char filename[] = "/tmp/fuzz-udev-rules.XXXXXX";
        int r;

        if (outside_size_range(size, /* lower= */ 0, 65536))
                return 0;

        fuzz_setup_logging();

        ASSERT_OK_ZERO(fmkostemp_safe(filename, "r+", &f));
        if (size != 0)
                ASSERT_EQ(fwrite(data, size, 1, f), 1U);
        fflush(f);

        rules = ASSERT_NOT_NULL(udev_rules_new(RESOLVE_NAME_EARLY));

        _cleanup_(conf_file_freep) ConfFile *c = NULL;
        ASSERT_OK(conf_file_new(filename, /* root= */ NULL, CONF_FILES_REGULAR, &c));

        r = udev_rules_parse_file(rules, c, /* extra_checks= */ false, /* ret= */ NULL);
        log_info_errno(r, "Parsing %s: %m", filename);
        ASSERT_TRUE(r >= 0 ||           /* OK */
                    r == -ENOBUFS);     /* line length exceeded */

        return 0;
}
