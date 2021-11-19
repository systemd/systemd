/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "architecture.h"
#include "glyph-util.h"
#include "gpt.h"
#include "log.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"
#include "util.h"

static void test_gpt_types_against_architectures(void) {
        const char *prefix;
        int r;

        log_info("/* %s */", __func__);

        /* Dumps a table indicating for which architectures we know we have matching GPT partition
         * types. Also validates whether we can properly categorize the entries. */

        FOREACH_STRING(prefix, "root-", "usr-")
                for (int a = 0; a < _ARCHITECTURE_MAX; a++) {
                        const char *suffix;

                        FOREACH_STRING(suffix, "", "-verity", "-verity-sig") {
                                _cleanup_free_ char *joined = NULL;
                                sd_id128_t id;

                                joined = strjoin(prefix, architecture_to_string(a), suffix);
                                if (!joined)
                                        return (void) log_oom();

                                r = gpt_partition_type_uuid_from_string(joined, &id);
                                if (r < 0) {
                                        printf("%s%s%s %s\n", ansi_highlight_red(), special_glyph(SPECIAL_GLYPH_CROSS_MARK), ansi_normal(), joined);
                                        continue;
                                }

                                printf("%s%s%s %s\n", ansi_highlight_green(), special_glyph(SPECIAL_GLYPH_CHECK_MARK), ansi_normal(), joined);

                                if (streq(prefix, "root-") && streq(suffix, ""))
                                        assert_se(gpt_partition_type_is_root(id));
                                if (streq(prefix, "root-") && streq(suffix, "-verity"))
                                        assert_se(gpt_partition_type_is_root_verity(id));
                                if (streq(prefix, "usr-") && streq(suffix, ""))
                                        assert_se(gpt_partition_type_is_usr(id));
                                if (streq(prefix, "usr-") && streq(suffix, "-verity"))
                                        assert_se(gpt_partition_type_is_usr_verity(id));
                        }
                }
}

int main(int argc, char *argv[]) {

        test_setup_logging(LOG_INFO);

        test_gpt_types_against_architectures();

        return 0;
}
