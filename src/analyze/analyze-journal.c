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

typedef struct {
        const char *name;
        uint64_t count;
} Field;

static int field_cmp(const Field *a, const Field *b) {
        return CMP(b->count, a->count);
}

static int analyze_data_objects(sd_journal *j) {
        Object *o;
        uint64_t p, c;
        const char *f;
        size_t n_fields = 0;
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        _cleanup_free_ Field *fields = NULL;
        int r;

        r = hashmap_ensure_allocated(&h, &string_hash_ops_free);
        if (r < 0)
                return log_oom();

        JOURNAL_FOREACH_OBJECT(j, o, p) {
                _unused_ _cleanup_free_ char *old_key = NULL;
                void *d;
                size_t l;

                if (o->object.type != OBJECT_DATA)
                        continue;

                r = journal_file_data_payload(j->objects_file, o, p, NULL, 0, j->data_threshold, &d, &l);
                if (r < 0)
                        return r;

                char *eq = memchr(d, '=', l);
                if (!eq)
                        return log_error_errno(
                                SYNTHETIC_ERRNO(ENOENT), "Data payload without '=': %.*s", (int) l, (char *) d);

                char *field = strndup(d, eq - (char *) d);
                if (!field)
                        return log_oom();

                c = (uint64_t) hashmap_get2(h, field, (void**) &old_key);

                /* ordered_hashmap_replace() does not fail when the hashmap already has the entry. */
                r = hashmap_replace(h, field, (void *) (c + 1));
                if (r < 0)
                        return r;

                TAKE_PTR(field);
        }

        fields = new(Field, hashmap_size(h));

        HASHMAP_FOREACH_KEY(c, f, h)
                fields[n_fields++] = (Field) { .name = f, .count = c };

        typesafe_qsort(fields, n_fields, field_cmp);

        for (size_t i = 0; i < n_fields; i++)
                printf("%s: %lu\n", fields[i].name, fields[i].count);

        return 0;
}

static int benchmark(sd_journal *j) {
        int total = 0;

        SD_JOURNAL_FOREACH(j) {
                const void *d;
                size_t l;

                SD_JOURNAL_FOREACH_DATA(j, d, l)
                        total += (int) l;
        }

        return total;
}

int verb_journal(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_journal_closep) sd_journal *system = NULL;
        // _cleanup_(sd_journal_closep) sd_journal *copy = NULL;
        int r;

        // r = sd_journal_open(&system, SD_JOURNAL_SYSTEM | SD_JOURNAL_LOCAL_ONLY);
        // if (r < 0)
        //         return r;

        r = sd_journal_open_directory(&system, "tmp/normal", 0);
        if (r < 0)
                return r;

        r = sd_journal_set_data_threshold(system, 0);
        if (r < 0)
                return r;

        r = benchmark(system);
        if (r < 0)
                return r;

        // r = analyze_object_usage(system);
        // if (r < 0)
        //         return r;

        // r = sd_journal_open_directory(&copy, ".", 0);
        // if (r < 0)
        //         return r;

        // r = sd_journal_set_data_threshold(copy, 0);
        // if (r < 0)
        //         return r;

        // r = analyze_object_usage(copy);
        // if (r < 0)
        //         return r;

        // r = analyze_data_objects(j);
        // if (r < 0)
        //         return r;

        return 0;
}
