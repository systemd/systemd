/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "homework-thin.h"
#include "tests.h"

TEST(pool_status) {
        HomeThinPoolStatus status;

        ASSERT_OK(home_thin_pool_parse_status(
                        "7 2/1024 8/4096 - rw discard_passdown error_if_no_space - 16",
                        &status));
        ASSERT_EQ(status.transaction_id, 7U);
        ASSERT_EQ(status.used_metadata, 2U);
        ASSERT_EQ(status.total_metadata, 1024U);
        ASSERT_EQ(status.used_data, 8U);
        ASSERT_EQ(status.total_data, 4096U);

        ASSERT_ERROR(home_thin_pool_parse_status("Fail", &status), EIO);
        ASSERT_ERROR(home_thin_pool_parse_status(
                             "7 2/1024 8/4096 - ro discard_passdown error_if_no_space - 16", &status),
                     EROFS);
        ASSERT_ERROR(home_thin_pool_parse_status(
                             "7 2/1024 8/4096 - rw no_discard_passdown error_if_no_space - 16", &status),
                     EOPNOTSUPP);
        ASSERT_ERROR(home_thin_pool_parse_status(
                             "7 2/1024 8/4096 - rw discard_passdown queue_if_no_space - 16", &status),
                     EOPNOTSUPP);
        ASSERT_ERROR(home_thin_pool_parse_status(
                             "7 2/1024 8/4096 - rw discard_passdown error_if_no_space needs_check 16", &status),
                     EUCLEAN);
}

TEST(pool_table) {
        ASSERT_OK(home_thin_pool_validate_table("253:0 253:1 512 128 1 error_if_no_space"));
        ASSERT_OK(home_thin_pool_validate_table(
                        "253:0 253:1 512 128 2 skip_block_zeroing error_if_no_space"));
        ASSERT_ERROR(home_thin_pool_validate_table("253:0 253:1 512 128"), EOPNOTSUPP);
        ASSERT_ERROR(home_thin_pool_validate_table("253:0 253:1 512 128 1 read_only"), EOPNOTSUPP);
        ASSERT_ERROR(home_thin_pool_validate_table(
                             "253:0 253:1 512 128 2 error_if_no_space no_discard_passdown"),
                     EOPNOTSUPP);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
