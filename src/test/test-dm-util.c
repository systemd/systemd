/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/sysmacros.h>

#include "dm-util.h"
#include "tests.h"

#define ROOT_HASH "4a2b7e1c9f0d3e5a6b8c7d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c"
#define TABLE "1 7:0 7:1 4096 4096 256 1 sha256 " ROOT_HASH " 9f86d081884c7d659a2feaa0c55ad015"

TEST(dm_verity_table_signed) {
        ASSERT_OK_ZERO(dm_verity_table_signed(TABLE, ROOT_HASH, /* ret_data_devnum= */ NULL));
        ASSERT_OK_ZERO(dm_verity_table_signed(TABLE " 2 ignore_zero_blocks check_at_most_once", ROOT_HASH, /* ret_data_devnum= */ NULL));
        ASSERT_OK_POSITIVE(dm_verity_table_signed(TABLE " 2 root_hash_sig_key_desc cryptsetup:abc-loop0", ROOT_HASH, /* ret_data_devnum= */ NULL));
        ASSERT_OK_POSITIVE(dm_verity_table_signed(TABLE " 3 ignore_zero_blocks root_hash_sig_key_desc cryptsetup:abc", ROOT_HASH, /* ret_data_devnum= */ NULL));
        ASSERT_OK_POSITIVE(dm_verity_table_signed(TABLE " 2 root_hash_sig_key_desc cryptsetup:abc", "4A2B7E1C9F0D3E5A6B8C7D9E0F1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C", /* ret_data_devnum= */ NULL));
        ASSERT_OK_POSITIVE(dm_verity_table_signed("1 7:0 7:1 4096 4096 256 1 sha256 " ROOT_HASH " - 2 root_hash_sig_key_desc cryptsetup:abc", ROOT_HASH, /* ret_data_devnum= */ NULL));

        /* The table declares one optional argument. root_hash_sig_key_desc comes after that argument, so
         * it must not mark the table as signed. */
        ASSERT_OK_ZERO(dm_verity_table_signed(TABLE " 1 ignore_zero_blocks root_hash_sig_key_desc", ROOT_HASH, /* ret_data_devnum= */ NULL));

        dev_t data_devnum;
        ASSERT_OK_POSITIVE(dm_verity_table_signed("1 259:3 7:1 4096 4096 256 1 sha256 " ROOT_HASH " - 2 root_hash_sig_key_desc cryptsetup:abc", ROOT_HASH, &data_devnum));
        ASSERT_EQ(data_devnum, makedev(259, 3));
        ASSERT_OK_ZERO(dm_verity_table_signed(TABLE, ROOT_HASH, &data_devnum));
        ASSERT_EQ(data_devnum, makedev(7, 0));
        ASSERT_ERROR(dm_verity_table_signed("1 sda 7:1 4096 4096 256 1 sha256 " ROOT_HASH " -", ROOT_HASH, &data_devnum), EINVAL);

        ASSERT_ERROR(dm_verity_table_signed(TABLE " 2 root_hash_sig_key_desc cryptsetup:abc", "00", /* ret_data_devnum= */ NULL), ESTALE);
        ASSERT_ERROR(dm_verity_table_signed("1 7:0 7:1 4096 4096 256 1 sha256", ROOT_HASH, /* ret_data_devnum= */ NULL), EBADMSG);
        ASSERT_ERROR(dm_verity_table_signed(TABLE " 3 ignore_zero_blocks", ROOT_HASH, /* ret_data_devnum= */ NULL), EBADMSG);
        ASSERT_ERROR(dm_verity_table_signed(TABLE " x", ROOT_HASH, /* ret_data_devnum= */ NULL), EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
