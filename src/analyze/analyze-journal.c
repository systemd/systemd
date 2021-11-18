/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "journal-util.h"
#include "analyze-journal.h"
#include "format-util.h"
#include "alloc-util.h"
#include "sort-util.h"
#include "format-table.h"

static int analyze_object_usage(sd_journal *j) {
        _cleanup_(table_unrefp) Table *t = NULL;
        uint64_t entries[_OBJECT_TYPE_MAX] = { 0 };
        size_t sizes[_OBJECT_TYPE_MAX] = { 0 };
        Object *o;
        size_t total_size = 0;
        uint64_t p, total_entries = 0;

        int r;

        JOURNAL_FOREACH_OBJECT(j, o, p) {
                entries[o->object.type]++;
                total_entries++;
                sizes[o->object.type] += le64toh(o->object.size);
                total_size += le64toh(o->object.size);
        }

        t = table_new("Object Type", "Entries", "Size");
        if (!t)
                return -ENOMEM;

        for (ObjectType type = 0; type < _OBJECT_TYPE_MAX; type++) {
                r = table_add_many(t,
                                   TABLE_STRING, journal_object_type_to_string(type),
                                   TABLE_UINT64, entries[type],
                                   TABLE_SIZE, sizes[type]);
                if (r < 0)
                        return r;
        }

        r = table_add_many(t, TABLE_STRING, "total", TABLE_UINT64, total_entries, TABLE_SIZE, total_size);
        if (r < 0)
                return r;

        r = table_print(t, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

static int journal_copy(sd_journal *j) {
        JournalMetrics metrics = { -1, -1, -1, -1, -1, -1 };
        MMapCache *mmap = NULL;
        JournalFile *to = NULL;
        int r;

        mmap = mmap_cache_new();
        if (!mmap) {
                r = log_oom();
                goto finish;
        };

        r = journal_file_open(
                -1, "copy.journal", O_RDWR | O_CREAT, 0640, true, UINT64_MAX, false, &metrics, mmap, NULL, NULL, &to);
        if (r < 0) {
                log_error_errno(r, "Failed to open journal: %m");
                goto finish;
        }

        SD_JOURNAL_FOREACH(j) {
                Object *o = NULL;
                JournalFile *from;

                from = j->current_file;
                assert(from && from->current_offset > 0);

                r = journal_file_move_to_object(from, OBJECT_ENTRY, from->current_offset, &o);
                if (r < 0) {
                        log_error_errno(r, "Can't read entry: %m");
                        goto finish;
                }

                r = journal_file_copy_entry(from, to, o, from->current_offset);
                if (r >= 0)
                        continue;

                log_info("Rotating journal.");

                r = journal_file_rotate(&to, true, UINT64_MAX, false, NULL);
                if (r < 0) {
                        log_error_errno(r, "Failed to rotate %s: %m", to->path);
                        goto finish;
                }

                log_debug("Retrying write.");
                r = journal_file_copy_entry(from, to, o, from->current_offset);
                if (r < 0) {
                        log_error_errno(r, "Can't write entry: %m");
                        goto finish;
                }
        }

        r = 0;

finish:
        journal_file_close(to);
        mmap_cache_unref(mmap);

        return r;
}

// typedef struct {
//         const char *name;
//         uint64_t count;
// } Field;

// static int field_cmp(const Field *a, const Field *b) {
//         return CMP(b->count, a->count);
// }

// static int analyze_data_objects(sd_journal *j) {
//         Object *o;
//         uint64_t p, c;
//         const char *f;
//         size_t n_fields = 0;
//         _cleanup_hashmap_free_ Hashmap *h = NULL;
//         _cleanup_free_ Field *fields = NULL;
//         int r;

//         r = hashmap_ensure_allocated(&h, &string_hash_ops_free);
//         if (r < 0)
//                 return log_oom();

//         JOURNAL_FOREACH_OBJECT(j, o, p) {
//                 _unused_ _cleanup_free_ char *old_key = NULL;
//                 void *d;
//                 size_t l;

//                 if (o->object.type != OBJECT_DATA)
//                         continue;

//                 r = journal_file_data_payload(j->objects_file, o, p, NULL, 0, j->data_threshold, &d, &l);
//                 if (r < 0)
//                         return r;

//                 char *eq = memchr(d, '=', l);
//                 if (!eq)
//                         return log_error_errno(
//                                 SYNTHETIC_ERRNO(ENOENT), "Data payload without '=': %.*s", (int) l, (char *) d);

//                 char *field = strndup(d, eq - (char *) d);
//                 if (!field)
//                         return log_oom();

//                 c = (uint64_t) hashmap_get2(h, field, (void**) &old_key);

//                 /* ordered_hashmap_replace() does not fail when the hashmap already has the entry. */
//                 r = hashmap_replace(h, field, (void *) (c + 1));
//                 if (r < 0)
//                         return r;

//                 TAKE_PTR(field);
//         }

//         fields = new(Field, hashmap_size(h));

//         HASHMAP_FOREACH_KEY(c, f, h)
//                 fields[n_fields++] = (Field) { .name = f, .count = c };

//         typesafe_qsort(fields, n_fields, field_cmp);

//         for (size_t i = 0; i < n_fields; i++)
//                 printf("%s: %lu\n", fields[i].name, fields[i].count);

//         return 0;
// }

int analyze_journal(void) {
        _cleanup_(sd_journal_closep) sd_journal *system = NULL;
        _cleanup_(sd_journal_closep) sd_journal *copy = NULL;
        int r;

        r = sd_journal_open(&system, SD_JOURNAL_SYSTEM | SD_JOURNAL_LOCAL_ONLY);
        if (r < 0)
                return r;

        r = sd_journal_set_data_threshold(system, 0);
        if (r < 0)
                return r;

        r = analyze_object_usage(system);
        if (r < 0)
                return r;

        r = journal_copy(system);
        if (r < 0)
                return r;

        r = sd_journal_open_directory(&copy, ".", 0);
        if (r < 0)
                return r;

        r = sd_journal_set_data_threshold(copy, 0);
        if (r < 0)
                return r;

        r = analyze_object_usage(copy);
        if (r < 0)
                return r;

        // r = analyze_data_objects(j);
        // if (r < 0)
        //         return r;

        return 0;
}
