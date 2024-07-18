/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "architecture.h"
#include "glyph-util.h"
#include "gpt.h"
#include "log.h"
#include "pretty-print.h"
#include "strv.h"
#include "terminal-util.h"
#include "tests.h"

TEST(gpt_types_against_abis) {
        int r;

        /* Dumps a table indicating for which abis we know we have matching GPT partition
         * types. Also validates whether we can properly categorize the entries. */

        FOREACH_STRING(prefix, "root-", "usr-")
                for (Abi a = 0; a < _ABI_MAX; a++)
                        FOREACH_STRING(suffix, "", "-verity", "-verity-sig") {
                                _cleanup_free_ char *joined = NULL;
                                GptPartitionType type;

                                joined = strjoin(prefix, abi_to_string(a), suffix);
                                if (!joined)
                                        return (void) log_oom();

                                r = gpt_partition_type_from_string(joined, &type);
                                if (r < 0) {
                                        printf("%s %s\n", RED_CROSS_MARK(), joined);
                                        continue;
                                }

                                printf("%s %s\n", GREEN_CHECK_MARK(), joined);

                                if (streq(prefix, "root-") && streq(suffix, ""))
                                        ASSERT_EQ(type.designator, PARTITION_ROOT);
                                if (streq(prefix, "root-") && streq(suffix, "-verity"))
                                        ASSERT_EQ(type.designator, PARTITION_ROOT_VERITY);
                                if (streq(prefix, "usr-") && streq(suffix, ""))
                                        ASSERT_EQ(type.designator, PARTITION_USR);
                                if (streq(prefix, "usr-") && streq(suffix, "-verity"))
                                        ASSERT_EQ(type.designator, PARTITION_USR_VERITY);

                                ASSERT_EQ(type.abi, a);
                        }
}

TEST(verity_mappings) {
        for (PartitionDesignator p = 0; p < _PARTITION_DESIGNATOR_MAX; p++) {
                PartitionDesignator q;

                q = partition_verity_of(p);
                assert_se(q < 0 || partition_verity_to_data(q) == p);

                q = partition_verity_sig_of(p);
                assert_se(q < 0 || partition_verity_sig_to_data(q) == p);

                q = partition_verity_to_data(p);
                assert_se(q < 0 || partition_verity_of(q) == p);

                q = partition_verity_sig_to_data(p);
                assert_se(q < 0 || partition_verity_sig_of(q) == p);
        }
}

TEST(type_alias_same) {
        /* Check that the partition type table is consistent, i.e. all aliases of the same partition type
         * carry the same metadata */

        for (const GptPartitionType *t = gpt_partition_type_table; t->name; t++) {
                GptPartitionType x, y;

                x = gpt_partition_type_from_uuid(t->uuid);                   /* seabi first by uuid */
                ASSERT_GE(gpt_partition_type_from_string(t->name, &y), 0); /* seabi first by name */

                ASSERT_EQ(t->abi, x.abi);
                ASSERT_EQ(t->abi, y.abi);
                ASSERT_EQ(t->designator, x.designator);
                ASSERT_EQ(t->designator, y.designator);
        }
}

TEST(override_abi) {
        GptPartitionType x, y;

        ASSERT_GE(gpt_partition_type_from_string("root-x86-64", &x), 0);
        ASSERT_EQ(x.abi, ABI_X86_64);

        ASSERT_GE(gpt_partition_type_from_string("root-arm64", &y), 0);
        ASSERT_EQ(y.abi, ABI_ARM64);

        x = gpt_partition_type_override_abi(x, ABI_ARM64);
        ASSERT_EQ(x.abi, y.abi);
        ASSERT_EQ(x.designator, y.designator);
        assert_se(sd_id128_equal(x.uuid, y.uuid));
        ASSERT_STREQ(x.name, y.name);

        /* If the partition type does not have an abi, nothing should change. */

        ASSERT_GE(gpt_partition_type_from_string("esp", &x), 0);
        y = x;

        x = gpt_partition_type_override_abi(x, ABI_ARM64);
        ASSERT_EQ(x.abi, y.abi);
        ASSERT_EQ(x.designator, y.designator);
        assert_se(sd_id128_equal(x.uuid, y.uuid));
        ASSERT_STREQ(x.name, y.name);
}

DEFINE_TEST_MAIN(LOG_INFO);
