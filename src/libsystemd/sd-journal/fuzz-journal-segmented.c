/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-journal.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "io-util.h"
#include "iovec-util.h"
#include "journal-def.h"
#include "journal-file.h"
#include "journal-file-util.h"
#include "journal-segmented.h"
#include "journal-segmented-internal.h"
#include "journal-verify.h"
#include "mmap-cache.h"
#include "siphash24.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "unaligned.h"

#define ENTRIES_MAX 256U

/* Almost every mutation fails a checksum before any interesting code runs, hence the input is also tried
 * with checksums and hashes fixed up. */
static void fix_checksums(uint8_t *p, size_t size) {
        Header *h = (Header*) p;
        uint64_t offset;

        if (size < sizeof(Header))
                return;

        offset = le64toh(h->header_size);

        while (offset <= size && size - offset >= sizeof(ObjectHeader)) {
                ObjectHeader *o = (ObjectHeader*) (p + offset);
                uint64_t sz = le64toh(o->size), checked = segmented_checked_size(o);

                if (sz < sizeof(ObjectHeader) || sz > size - offset || sz < checked)
                        break;

                /* Make uncompressed payloads match their hash too */
                if (o->type == OBJECT_DATA && (o->flags & _OBJECT_COMPRESSED_MASK) == 0)
                        unaligned_write_le64(
                                        p + offset + offsetof(SegmentedDataObject, hash),
                                        siphash24(p + offset + checked, sz - checked, h->file_id.bytes));

                if (o->type == OBJECT_INDEX)
                        unaligned_write_le32(
                                        p + offset + offsetof(IndexObject, payload_checksum),
                                        segmented_payload_checksum(h->file_id, p + offset + checked, sz - checked));

                o->checksum = htole32(segmented_checksum_with_file_id(h->file_id, offset, o, checked));

                if (ALIGN64(sz) < sz)
                        break;
                offset += ALIGN64(sz);
        }
}

static void make_file(char *name, const uint8_t *data, size_t size) {
        _cleanup_close_ int fd = -EBADF;

        /* Unlinked files are refused, hence no memfd. */
        assert_se((fd = mkostemp_safe(name)) >= 0);
        assert_se(loop_write(fd, data, size) >= 0);
}

static void read_journal(const char *name) {
        _cleanup_(sd_journal_closep) sd_journal *j = NULL;
        _cleanup_free_ char *cursor = NULL, *match = NULL;
        uint64_t realtime = 0, monotonic = 0;
        sd_id128_t boot_id = SD_ID128_NULL;
        const void *data;
        const char *field;
        size_t size, match_size = 0;
        unsigned n;

        if (sd_journal_open_files(&j, (const char*[]) { name, NULL }, 0) < 0)
                return;

        n = 0;
        SD_JOURNAL_FOREACH(j) {
                if (n++ >= ENTRIES_MAX)
                        break;

                (void) sd_journal_get_realtime_usec(j, &realtime);
                (void) sd_journal_get_monotonic_usec(j, &monotonic, &boot_id);

                SD_JOURNAL_FOREACH_DATA(j, data, size)
                        if (!match && size > 0 && size < 4096 && memchr(data, '=', size)) {
                                match = memdup(data, size);
                                match_size = size;
                        }

                if (!cursor)
                        (void) sd_journal_get_cursor(j, &cursor);
        }

        n = 0;
        SD_JOURNAL_FOREACH_BACKWARDS(j) {
                if (n++ >= ENTRIES_MAX)
                        break;

                (void) sd_journal_get_data(j, "MESSAGE", &data, &size);
        }

        if (sd_journal_seek_realtime_usec(j, realtime) >= 0) {
                (void) sd_journal_next(j);
                (void) sd_journal_previous_skip(j, 3);
        }

        if (sd_journal_seek_monotonic_usec(j, boot_id, monotonic) >= 0) {
                (void) sd_journal_previous(j);
                (void) sd_journal_next_skip(j, 3);
        }

        if (cursor && sd_journal_seek_cursor(j, cursor) >= 0) {
                (void) sd_journal_next(j);
                (void) sd_journal_test_cursor(j, cursor);
        }

        if (match && sd_journal_add_match(j, match, match_size) >= 0) {
                n = 0;
                SD_JOURNAL_FOREACH(j)
                        if (n++ >= ENTRIES_MAX)
                                break;

                (void) sd_journal_add_disjunction(j);
                (void) sd_journal_add_match(j, "PRIORITY=6", SIZE_MAX);
                (void) sd_journal_add_conjunction(j);
                (void) sd_journal_add_match(j, "_BOOT_ID=00000000000000000000000000000000", SIZE_MAX);

                n = 0;
                SD_JOURNAL_FOREACH_BACKWARDS(j)
                        if (n++ >= ENTRIES_MAX)
                                break;

                if (sd_journal_seek_monotonic_usec(j, boot_id, monotonic) >= 0)
                        (void) sd_journal_next(j);

                sd_journal_flush_matches(j);

                _cleanup_free_ char *unique = memdup_suffix0(match, (const char*) memchr(match, '=', match_size) - match);
                if (unique && sd_journal_query_unique(j, unique) >= 0) {
                        n = 0;
                        SD_JOURNAL_FOREACH_UNIQUE(j, data, size)
                                if (n++ >= ENTRIES_MAX)
                                        break;
                }
        }

        n = 0;
        SD_JOURNAL_FOREACH_FIELD(j, field)
                if (n++ >= ENTRIES_MAX)
                        break;
}

static void verify_journal(MMapCache *m, const char *name) {
        JournalFile *f = NULL;

        if (journal_file_open(-EBADF, name, O_RDONLY, 0, 0, UINT64_MAX, NULL, m, NULL, &f) < 0)
                return;

        (void) journal_file_verify(f, NULL, NULL, NULL, NULL, /* show_progress= */ false);
        (void) journal_file_close(f);
}

static void write_journal(MMapCache *m, const char *name) {
        static const sd_id128_t boot_id = SD_ID128_MAKE(f0,0d,f0,0d,f0,0d,f0,0d,f0,0d,f0,0d,f0,0d,f0,0d);
        JournalFile *f = NULL;

        /* Continue the file, as journald does after a restart. */

        if (journal_file_open(-EBADF, name, O_RDWR, 0, 0, UINT64_MAX, NULL, m, NULL, &f) < 0)
                return;

        for (unsigned i = 0; i < 3; i++) {
                dual_timestamp ts = {
                        .realtime = le64toh(f->header->tail_entry_realtime) + 1,
                        .monotonic = le64toh(f->header->tail_entry_monotonic) + 1,
                };
                struct iovec iovec[] = {
                        IOVEC_MAKE_STRING("MESSAGE=fuzz"),
                        IOVEC_MAKE_STRING("_TRANSPORT=journal"),
                        IOVEC_MAKE_STRING("_UID=0"),
                        IOVEC_MAKE_STRING(i == 0 ? "NUMBER=0" : "NUMBER=1"),
                };

                if (journal_file_append_entry(f, &ts, &boot_id, iovec, ELEMENTSOF(iovec), NULL, NULL, NULL, NULL) < 0)
                        break;

                if (i == 1)
                        (void) segmented_checkpoint(f);
        }

        (void) journal_file_set_offline(f, /* wait= */ true);

        /* journal_file_archive() would rename the file. Setting the flag is enough to merge the indexes. */
        f->archive = true;
        (void) journal_file_set_offline(f, /* wait= */ true);

        (void) journal_file_offline_close(f);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        _cleanup_free_ uint8_t *fixed = NULL;

        if (outside_size_range(size, sizeof(Header), 1024 * 1024))
                return 0;

        if (!FLAGS_SET(le32toh(((const Header*) data)->incompatible_flags), HEADER_INCOMPATIBLE_SEGMENTED))
                return 0;

        fuzz_setup_logging();

        assert_se(m = mmap_cache_new());
        assert_se(fixed = memdup(data, size));
        fix_checksums(fixed, size);

        const uint8_t *p;
        FOREACH_ARGUMENT(p, data, (const uint8_t*) fixed) {
                _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-journal-segmented.XXXXXX";

                make_file(name, p, size);
                read_journal(name);
                verify_journal(m, name);
        }

        /* Continue a copy of the fixed input through the writer, then check what it left behind. */
        _cleanup_(unlink_tempfilep) char name[] = "/tmp/fuzz-journal-segmented.XXXXXX";

        make_file(name, fixed, size);
        write_journal(m, name);
        read_journal(name);
        verify_journal(m, name);

        return 0;
}
