/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "architecture.h"
#include "fd-util.h"
#include "gpt.h"
#include "log.h"
#include "memfd-util.h"
#include "memory-util.h"
#include "pretty-print.h"
#include "strv.h"
#include "tests.h"

TEST(gpt_types_against_architectures) {
        int r;

        /* Dumps a table indicating for which architectures we know we have matching GPT partition
         * types. Also validates whether we can properly categorize the entries. */

        FOREACH_STRING(prefix, "root-", "usr-")
                for (Architecture a = 0; a < _ARCHITECTURE_MAX; a++)
                        FOREACH_STRING(suffix, "", "-verity", "-verity-sig") {
                                _cleanup_free_ char *joined = NULL;
                                GptPartitionType type;

                                joined = strjoin(prefix, architecture_to_string(a), suffix);
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

                                ASSERT_EQ(type.arch, a);
                        }
}

TEST(verity_mappings) {
        for (PartitionDesignator p = 0; p < _PARTITION_DESIGNATOR_MAX; p++) {
                PartitionDesignator q;

                q = partition_verity_hash_of(p);
                ASSERT_TRUE(q < 0 || partition_verity_hash_to_data(q) == p);

                q = partition_verity_sig_of(p);
                ASSERT_TRUE(q < 0 || partition_verity_sig_to_data(q) == p);

                q = partition_verity_hash_to_data(p);
                ASSERT_TRUE(q < 0 || partition_verity_hash_of(q) == p);

                q = partition_verity_sig_to_data(p);
                ASSERT_TRUE(q < 0 || partition_verity_sig_of(q) == p);

                q = partition_verity_to_data(p);
                ASSERT_TRUE(q < 0 || partition_verity_hash_of(q) == p || partition_verity_sig_of(q) == p);
        }
}

TEST(type_alias_same) {
        /* Check that the partition type table is consistent, i.e. all aliases of the same partition type
         * carry the same metadata */

        for (const GptPartitionType *t = gpt_partition_type_table; t->name; t++) {
                GptPartitionType x, y;

                x = gpt_partition_type_from_uuid(t->uuid);                   /* search first by uuid */
                ASSERT_GE(gpt_partition_type_from_string(t->name, &y), 0); /* search first by name */

                ASSERT_EQ(t->arch, x.arch);
                ASSERT_EQ(t->arch, y.arch);
                ASSERT_EQ(t->designator, x.designator);
                ASSERT_EQ(t->designator, y.designator);
        }
}

TEST(override_architecture) {
        GptPartitionType x, y;

        ASSERT_GE(gpt_partition_type_from_string("root-x86-64", &x), 0);
        ASSERT_EQ(x.arch, ARCHITECTURE_X86_64);

        ASSERT_GE(gpt_partition_type_from_string("root-arm64", &y), 0);
        ASSERT_EQ(y.arch, ARCHITECTURE_ARM64);

        x = gpt_partition_type_override_architecture(x, ARCHITECTURE_ARM64);
        ASSERT_EQ(x.arch, y.arch);
        ASSERT_EQ(x.designator, y.designator);
        ASSERT_EQ_ID128(x.uuid, y.uuid);
        ASSERT_STREQ(x.name, y.name);

        /* If the partition type does not have an architecture, nothing should change. */

        ASSERT_GE(gpt_partition_type_from_string("esp", &x), 0);
        y = x;

        x = gpt_partition_type_override_architecture(x, ARCHITECTURE_ARM64);
        ASSERT_EQ(x.arch, y.arch);
        ASSERT_EQ(x.designator, y.designator);
        ASSERT_EQ_ID128(x.uuid, y.uuid);
        ASSERT_STREQ(x.name, y.name);
}

static void make_gpt(int fd, uint32_t sector_size, const GptPartitionEntry *part_entries, size_t n_entries) {
        /* Zero-fill enough for header probing (gpt_probe reads 2*4096 = 8KB) */
        static const uint8_t zeros[2 * 4096] = {};
        ASSERT_OK_EQ_ERRNO(pwrite(fd, zeros, sizeof(zeros), 0), (ssize_t) sizeof(zeros));

        GptHeader h = {
                .signature = { 'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T' },
                .revision = htole32(UINT32_C(0x00010000)),
                .header_size = htole32(sizeof(GptHeader)),
                .my_lba = htole64(1),
                .partition_entry_lba = htole64(2),
                .number_of_partition_entries = htole32(n_entries),
                .size_of_partition_entry = htole32(sizeof(GptPartitionEntry)),
        };
        ASSERT_OK_EQ_ERRNO(pwrite(fd, &h, sizeof(h), sector_size), (ssize_t) sizeof(h));

        if (n_entries > 0) {
                size_t entries_size = n_entries * sizeof(GptPartitionEntry);
                ASSERT_OK_EQ_ERRNO(pwrite(fd, part_entries, entries_size, 2 * sector_size), (ssize_t) entries_size);
        }
}

TEST(gpt_probe_empty) {
        _cleanup_close_ int fd = -EBADF;

        fd = ASSERT_OK(memfd_new("test-gpt-probe"));
        ASSERT_OK_EQ(gpt_probe(fd, /* ret_header= */ NULL, /* ret_entries= */ NULL, /* ret_n_entries= */ NULL, /* ret_entry_size= */ NULL), (ssize_t) 0);
}

TEST(gpt_probe_too_short) {
        _cleanup_close_ int fd = -EBADF;
        static const uint8_t buf[4096] = {};

        fd = ASSERT_OK(memfd_new("test-gpt-probe"));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, buf, sizeof(buf), 0), (ssize_t) sizeof(buf));
        ASSERT_OK_EQ(gpt_probe(fd, /* ret_header= */ NULL, /* ret_entries= */ NULL, /* ret_n_entries= */ NULL, /* ret_entry_size= */ NULL), (ssize_t) 0);
}

TEST(gpt_probe_no_signature) {
        _cleanup_close_ int fd = -EBADF;
        static const uint8_t buf[2 * 4096] = {};

        fd = ASSERT_OK(memfd_new("test-gpt-probe"));
        ASSERT_OK_EQ_ERRNO(pwrite(fd, buf, sizeof(buf), 0), (ssize_t) sizeof(buf));
        ASSERT_OK_EQ(gpt_probe(fd, /* ret_header= */ NULL, /* ret_entries= */ NULL, /* ret_n_entries= */ NULL, /* ret_entry_size= */ NULL), (ssize_t) 0);
}

TEST(gpt_probe_sector_512) {
        _cleanup_close_ int fd = -EBADF;

        const GptPartitionEntry entries[2] = {
                {
                        .unique_partition_guid = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 },
                        .starting_lba = htole64(100),
                        .ending_lba = htole64(200),
                },
                {
                        .unique_partition_guid = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                                   0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 },
                        .starting_lba = htole64(300),
                        .ending_lba = htole64(400),
                },
        };

        fd = ASSERT_OK(memfd_new("test-gpt-probe"));
        make_gpt(fd, 512, entries, 2);

        /* Sector size detection only */
        ASSERT_OK_EQ(gpt_probe(fd, /* ret_header= */ NULL, /* ret_entries= */ NULL, /* ret_n_entries= */ NULL, /* ret_entry_size= */ NULL), (ssize_t) 512);

        /* Header return */
        GptHeader h;
        ASSERT_OK_EQ(gpt_probe(fd, &h, /* ret_entries= */ NULL, /* ret_n_entries= */ NULL, /* ret_entry_size= */ NULL), (ssize_t) 512);
        ASSERT_EQ(le32toh(h.number_of_partition_entries), 2u);
        ASSERT_EQ(le32toh(h.size_of_partition_entry), (uint32_t) sizeof(GptPartitionEntry));

        /* Full probe with entries */
        _cleanup_free_ void *ret_entries = NULL;
        uint32_t n, sz;
        ASSERT_OK_EQ(gpt_probe(fd, /* ret_header= */ NULL, &ret_entries, &n, &sz), (ssize_t) 512);
        ASSERT_EQ(n, 2u);
        ASSERT_EQ(sz, (uint32_t) sizeof(GptPartitionEntry));
        ASSERT_NOT_NULL(ret_entries);

        GptPartitionEntry *e = ret_entries;
        ASSERT_EQ(memcmp_nn(e[0].unique_partition_guid, sizeof(e[0].unique_partition_guid), entries[0].unique_partition_guid, sizeof(entries[0].unique_partition_guid)), 0);
        ASSERT_EQ(memcmp_nn(e[1].unique_partition_guid, sizeof(e[1].unique_partition_guid), entries[1].unique_partition_guid, sizeof(entries[1].unique_partition_guid)), 0);
        ASSERT_EQ(le64toh(e[0].starting_lba), UINT64_C(100));
        ASSERT_EQ(le64toh(e[1].starting_lba), UINT64_C(300));
}

TEST(gpt_probe_sector_4096) {
        _cleanup_close_ int fd = -EBADF;

        const GptPartitionEntry entry = {
                .unique_partition_guid = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                                           0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 },
                .starting_lba = htole64(50),
                .ending_lba = htole64(100),
        };

        fd = ASSERT_OK(memfd_new("test-gpt-probe"));
        make_gpt(fd, 4096, &entry, 1);

        ASSERT_OK_EQ(gpt_probe(fd, /* ret_header= */ NULL, /* ret_entries= */ NULL, /* ret_n_entries= */ NULL, /* ret_entry_size= */ NULL), (ssize_t) 4096);

        _cleanup_free_ void *ret_entries = NULL;
        uint32_t n, sz;
        ASSERT_OK_EQ(gpt_probe(fd, /* ret_header= */ NULL, &ret_entries, &n, &sz), (ssize_t) 4096);
        ASSERT_EQ(n, 1u);

        GptPartitionEntry *e = ret_entries;
        ASSERT_EQ(memcmp_nn(e[0].unique_partition_guid, sizeof(e[0].unique_partition_guid), entry.unique_partition_guid, sizeof(entry.unique_partition_guid)), 0);
        ASSERT_EQ(le64toh(e[0].starting_lba), UINT64_C(50));
}

TEST(gpt_probe_ambiguous) {
        _cleanup_close_ int fd = -EBADF;

        const GptPartitionEntry entry = {};

        fd = ASSERT_OK(memfd_new("test-gpt-probe"));
        make_gpt(fd, 512, &entry, 1);

        /* Place a second valid header at offset 4096 */
        GptHeader h2 = {
                .signature = { 'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T' },
                .revision = htole32(UINT32_C(0x00010000)),
                .header_size = htole32(sizeof(GptHeader)),
                .my_lba = htole64(1),
                .partition_entry_lba = htole64(2),
                .number_of_partition_entries = htole32(1),
                .size_of_partition_entry = htole32(sizeof(GptPartitionEntry)),
        };
        ASSERT_OK_EQ_ERRNO(pwrite(fd, &h2, sizeof(h2), 4096), (ssize_t) sizeof(h2));

        ASSERT_ERROR(gpt_probe(fd, /* ret_header= */ NULL, /* ret_entries= */ NULL, /* ret_n_entries= */ NULL, /* ret_entry_size= */ NULL), ENOTUNIQ);
}

DEFINE_TEST_MAIN(LOG_INFO);
