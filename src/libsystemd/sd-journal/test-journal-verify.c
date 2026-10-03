/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ansi-color.h"
#include "chattr-util.h"
#include "fd-util.h"
#include "iovec-util.h"
#include "journal-authenticate.h"
#include "journal-file-util.h"
#include "journal-verify.h"
#include "log.h"
#include "mmap-cache.h"
#include "rm-rf.h"
#include "tests.h"
#include "time-util.h"

#define N_ENTRIES 6000
#define RANDOM_RANGE 77

static void bit_toggle(const char *fn, uint64_t p) {
        uint8_t b;
        int fd;

        ASSERT_OK_ERRNO(fd = open(fn, O_RDWR|O_CLOEXEC));

        ASSERT_EQ(pread(fd, &b, 1, p/8), 1);

        b ^= 1 << (p % 8);

        ASSERT_EQ(pwrite(fd, &b, 1, p/8), 1);

        safe_close(fd);
}

static int raw_verify(const char *fn, const char *verification_key) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        JournalFile *f;
        int r;

        ASSERT_NOT_NULL(m = mmap_cache_new());

        r = journal_file_open(
                        /* fd= */ -EBADF,
                        fn,
                        O_RDONLY,
                        JOURNAL_COMPRESS|(verification_key ? JOURNAL_SEAL : 0),
                        0666,
                        /* compress_threshold_bytes= */ UINT64_MAX,
                        /* metrics= */ NULL,
                        m,
                        /* template= */ NULL,
                        &f);
        if (r < 0)
                return r;

        r = journal_file_verify(f, verification_key, NULL, NULL, NULL, false);
        (void) journal_file_close(f);

        return r;
}

static int run_test(const char *verification_key, ssize_t max_iterations) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        char t[] = "/var/tmp/journal-XXXXXX";
        struct stat st;
        JournalFile *f;
        JournalFile *df;
        usec_t from = 0, to = 0, total = 0;
        uint64_t start, end;
        int r;

        ASSERT_NOT_NULL(m = mmap_cache_new());

        /* journal_file_open() requires a valid machine id */
        if (sd_id128_get_machine(NULL) < 0)
                return log_tests_skipped("No valid machine ID found");

        test_setup_logging(LOG_DEBUG);

        ASSERT_NOT_NULL(mkdtemp(t));
        ASSERT_OK_ERRNO(chdir(t));
        (void) chattr_path(t, FS_NOCOW_FL, FS_NOCOW_FL);

        log_info("Generating a test journal");

        ASSERT_OK_ZERO(journal_file_open(
                                /* fd= */ -EBADF,
                                "test.journal",
                                O_RDWR|O_CREAT,
                                JOURNAL_COMPRESS|(verification_key ? JOURNAL_SEAL : 0),
                                0666,
                                /* compress_threshold_bytes= */ UINT64_MAX,
                                /* metrics= */ NULL,
                                m,
                                /* template= */ NULL,
                                &df));

        for (size_t n = 0; n < N_ENTRIES; n++) {
                _cleanup_free_ char *test = NULL;
                struct iovec iovec;
                struct dual_timestamp ts;

                dual_timestamp_now(&ts);
                ASSERT_OK_ERRNO(asprintf(&test, "RANDOM=%li", random() % RANDOM_RANGE));
                iovec = IOVEC_MAKE_STRING(test);
                ASSERT_OK_ZERO(journal_file_append_entry(
                                        df,
                                        &ts,
                                        /* boot_id= */ NULL,
                                        &iovec,
                                        /* n_iovec= */ 1,
                                        /* seqnum= */ NULL,
                                        /* seqnum_id= */ NULL,
                                        /* ret_object= */ NULL,
                                        /* ret_offset= */ NULL));
        }

        (void) journal_file_offline_close(df);

        log_info("Verifying with key: %s", strna(verification_key));

        ASSERT_OK_ZERO(journal_file_open(
                                /* fd= */ -EBADF,
                                "test.journal",
                                O_RDONLY,
                                JOURNAL_COMPRESS|(verification_key ? JOURNAL_SEAL : 0),
                                0666,
                                /* compress_threshold_bytes= */ UINT64_MAX,
                                /* metrics= */ NULL,
                                m,
                                /* template= */ NULL,
                                &f));
        journal_file_print_header(f);
        journal_file_dump(f);

        ASSERT_OK(journal_file_verify(f, verification_key, &from, &to, &total, true));

        if (verification_key && JOURNAL_HEADER_SEALED(f->header))
                log_info("=> Validated from %s to %s, %s missing",
                         FORMAT_TIMESTAMP(from),
                         FORMAT_TIMESTAMP(to),
                         FORMAT_TIMESPAN(total > to ? total - to : 0, 0));

        (void) journal_file_close(f);
        ASSERT_OK_ERRNO(stat("test.journal", &st));

        start = 38448 * 8 + 0;
        end = max_iterations < 0 ? (uint64_t)st.st_size * 8 : start + max_iterations;
        log_info("Toggling bits %"PRIu64 " to %"PRIu64, start, end);

        for (uint64_t p = start; p < end; p++) {
                bit_toggle("test.journal", p);

                if (max_iterations < 0)
                        log_info("[ %"PRIu64"+%"PRIu64"]", p / 8, p % 8);

                r = raw_verify("test.journal", verification_key);
                /* Suppress the notice when running in the limited (CI) mode */
                if (verification_key && max_iterations < 0 && r >= 0)
                        log_notice(ANSI_HIGHLIGHT_RED ">>>> %"PRIu64" (bit %"PRIu64") can be toggled without detection." ANSI_NORMAL, p / 8, p % 8);

                bit_toggle("test.journal", p);
        }

        ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));

        return 0;
}

static void write_entry_array_item(int fd, uint64_t slot, size_t item_size, uint64_t v) {
        le64_t v64 = htole64(v);
        le32_t v32 = htole32(v);

        ASSERT_EQ(pwrite(fd, item_size == sizeof(v32) ? (void*) &v32 : (void*) &v64, item_size, slot),
                  (ssize_t) item_size);
}

static void test_entry_reference_one(bool in_data_object) {
        _cleanup_(mmap_cache_unrefp) MMapCache *m = NULL;
        char t[] = "/var/tmp/journal-XXXXXX";
        const char *field = "REFERENCE=shared";
        uint64_t a, i, target, data = 0, n_entries, last = 0, slot = 0;
        size_t item_size;
        JournalFile *f;
        Object *o;
        int fd;

        ASSERT_NOT_NULL(m = mmap_cache_new());

        ASSERT_NOT_NULL(mkdtemp(t));
        ASSERT_OK_ERRNO(chdir(t));

        ASSERT_OK_ZERO(journal_file_open(
                                /* fd= */ -EBADF,
                                "test.journal",
                                O_RDWR|O_CREAT,
                                /* file_flags= */ 0,
                                0666,
                                /* compress_threshold_bytes= */ UINT64_MAX,
                                /* metrics= */ NULL,
                                m,
                                /* template= */ NULL,
                                &f));

        /* Three entries with the same field, i.e. one data object that references all of them */
        for (size_t k = 0; k < 3; k++) {
                struct iovec iovec = IOVEC_MAKE_STRING(field);
                struct dual_timestamp ts;

                dual_timestamp_now(&ts);
                ASSERT_OK_ZERO(journal_file_append_entry(
                                        f,
                                        &ts,
                                        /* boot_id= */ NULL,
                                        &iovec,
                                        /* n_iovec= */ 1,
                                        /* seqnum= */ NULL,
                                        /* seqnum_id= */ NULL,
                                        /* ret_object= */ NULL,
                                        /* ret_offset= */ NULL));
        }

        item_size = journal_file_entry_array_item_size(f);

        /* For the main entry array, find the slot of the last entry. For the entry array of the data object,
         * find the first unused slot, and the entry in the slot before it. Note that the first entry of a
         * data object is stored in the object itself, not in its entry array. */
        if (in_data_object) {
                ASSERT_EQ(journal_file_find_data_object(f, field, strlen(field), &o, &data), 1);
                n_entries = le64toh(o->data.n_entries);
                a = le64toh(o->data.entry_array_offset);
                i = 1;
                target = n_entries;
        } else {
                n_entries = le64toh(f->header->n_entries);
                a = le64toh(f->header->entry_array_offset);
                i = 0;
                target = n_entries - 1;
        }
        ASSERT_EQ(n_entries, 3u);

        while (a != 0 && slot == 0) {
                ASSERT_OK(journal_file_move_to_object(f, OBJECT_ENTRY_ARRAY, a, &o));

                for (uint64_t j = 0; j < journal_file_entry_array_n_items(f, o); j++, i++) {
                        if (i == target) {
                                slot = a + offsetof(Object, entry_array.items) + j * item_size;
                                break;
                        }

                        last = journal_file_entry_array_item(f, o, j);
                }

                a = le64toh(o->entry_array.next_entry_array_offset);
        }

        ASSERT_NE(last, 0u);
        ASSERT_NE(slot, 0u);
        (void) journal_file_offline_close(f);

        ASSERT_OK_ERRNO(fd = open("test.journal", O_RDWR|O_CLOEXEC));
        if (in_data_object) {
                /* Give the data object one more reference, to something that is not an entry object. All
                 * existing references stay intact, hence this is only noticed when the entries a data
                 * object references are checked. */
                le64_t n = htole64(n_entries + 1);

                write_entry_array_item(fd, slot, item_size, last + 8);
                ASSERT_EQ(pwrite(fd, &n, sizeof(n), data + offsetof(Object, data.n_entries)),
                          (ssize_t) sizeof(n));
        } else
                /* Unlink the last entry from the main entry array. The entry object itself is intact, and
                 * the data object still references it. This is noticed when the main entry array is
                 * checked, which is why the entries referenced by data objects don't have to be looked up
                 * in the main entry array again. */
                write_entry_array_item(fd, slot, item_size, 0);
        safe_close(fd);

        ASSERT_ERROR(raw_verify("test.journal", /* verification_key= */ NULL), EBADMSG);

        ASSERT_OK(rm_rf(t, REMOVE_ROOT|REMOVE_PHYSICAL));
}

static void test_entry_reference(void) {
        if (sd_id128_get_machine(NULL) < 0)
                return (void) log_tests_skipped("No valid machine ID found");

        test_setup_logging(LOG_DEBUG);

        test_entry_reference_one(/* in_data_object= */ false);
        test_entry_reference_one(/* in_data_object= */ true);
}

int main(int argc, char *argv[]) {
        const char *verification_key = NULL;
        int max_iterations = 512;

        journal_auth_init();

        if (argc > 1) {
                /* Don't limit the number of iterations when the verification key
                 * is provided on the command line, we want to do that only in CIs */
                verification_key = argv[1];
                max_iterations = -1;
        }

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1));
        run_test(verification_key, max_iterations);

        ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1));
        run_test(verification_key, max_iterations);

        /* If we're running without any arguments and journal sealing support is enabled,
         * check the journal verification stuff with a valid key as well */
        if (argc <= 1 && journal_auth_supported()) {
                verification_key = "c262bd-85187f-0b1b04-877cc5/1c7af8-35a4e900";

                ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "0", 1));
                run_test(verification_key, max_iterations);

                ASSERT_OK_ERRNO(setenv("SYSTEMD_JOURNAL_COMPACT", "1", 1));
                run_test(verification_key, max_iterations);
        }

        test_entry_reference();

        return 0;
}
