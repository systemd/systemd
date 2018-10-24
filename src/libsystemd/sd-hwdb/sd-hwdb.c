/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2008 Alan Jenkins <alan.christopher.jenkins@googlemail.com>
***/

#include <errno.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "sd-hwdb.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "hwdb-internal.h"
#include "hwdb-util.h"
#include "refcnt.h"
#include "string-util.h"
#include "util.h"

struct sd_hwdb {
        RefCount n_ref;

        FILE *f;
        struct stat st;
        union {
                struct trie_header_f *head;
                const char *map;
        };

        OrderedHashmap *properties;
        Iterator properties_iterator;
        bool properties_modified;
};

struct linebuf {
        char bytes[LINE_MAX];
        size_t size;
        size_t len;
};

static void linebuf_init(struct linebuf *buf) {
        buf->size = 0;
        buf->len = 0;
}

static const char *linebuf_get(struct linebuf *buf) {
        if (buf->len + 1 >= sizeof(buf->bytes))
                return NULL;
        buf->bytes[buf->len] = '\0';
        return buf->bytes;
}

static bool linebuf_add(struct linebuf *buf, const char *s, size_t len) {
        if (buf->len + len >= sizeof(buf->bytes))
                return false;
        memcpy(buf->bytes + buf->len, s, len);
        buf->len += len;
        return true;
}

static bool linebuf_add_char(struct linebuf *buf, char c) {
        if (buf->len + 1 >= sizeof(buf->bytes))
                return false;
        buf->bytes[buf->len++] = c;
        return true;
}

static void linebuf_rem(struct linebuf *buf, size_t count) {
        assert(buf->len >= count);
        buf->len -= count;
}

static void linebuf_rem_char(struct linebuf *buf) {
        linebuf_rem(buf, 1);
}

static const struct trie_child_entry_f *trie_node_child(sd_hwdb *hwdb, const struct trie_node_f *node, size_t idx) {
        const char *base = (const char *)node;

        base += le64toh(hwdb->head->node_size);
        base += idx * le64toh(hwdb->head->child_entry_size);
        return (const struct trie_child_entry_f *)base;
}

static const struct trie_value_entry_f *trie_node_value(sd_hwdb *hwdb, const struct trie_node_f *node, size_t idx) {
        const char *base = (const char *)node;

        base += le64toh(hwdb->head->node_size);
        base += node->children_count * le64toh(hwdb->head->child_entry_size);
        base += idx * le64toh(hwdb->head->value_entry_size);
        return (const struct trie_value_entry_f *)base;
}

static const struct trie_node_f *trie_node_from_off(sd_hwdb *hwdb, le64_t off) {
        return (const struct trie_node_f *)(hwdb->map + le64toh(off));
}

static const char *trie_string(sd_hwdb *hwdb, le64_t off) {
        return hwdb->map + le64toh(off);
}

static int trie_children_cmp_f(const void *v1, const void *v2) {
        const struct trie_child_entry_f *n1 = v1;
        const struct trie_child_entry_f *n2 = v2;

        return n1->c - n2->c;
}

static const struct trie_node_f *node_lookup_f(sd_hwdb *hwdb, const struct trie_node_f *node, uint8_t c) {
        struct trie_child_entry_f *child;
        struct trie_child_entry_f search;

        search.c = c;
        child = bsearch(&search, (const char *)node + le64toh(hwdb->head->node_size), node->children_count,
                        le64toh(hwdb->head->child_entry_size), trie_children_cmp_f);
        if (child)
                return trie_node_from_off(hwdb, child->child_off);
        return NULL;
}

static int hwdb_add_property(sd_hwdb *hwdb, const struct trie_value_entry_f *entry) {
        const char *key;
        int r;

        assert(hwdb);

        key = trie_string(hwdb, entry->key_off);

        /*
         * Silently ignore all properties which do not start with a
         * space; future extensions might use additional prefixes.
         */
        if (key[0] != ' ')
                return 0;

        key++;

        if (le64toh(hwdb->head->value_entry_size) >= sizeof(struct trie_value_entry2_f)) {
                const struct trie_value_entry2_f *old, *entry2;

                entry2 = (const struct trie_value_entry2_f *)entry;
                old = ordered_hashmap_get(hwdb->properties, key);
                if (old) {
                        /* On duplicates, we order by filename priority and line-number.
                         *
                         * v2 of the format had 64 bits for the line number.
                         * v3 reuses top 32 bits of line_number to store the priority.
                         * We check the top bits — if they are zero we have v2 format.
                         * This means that v2 clients will print wrong line numbers with
                         * v3 data.
                         *
                         * For v3 data: we compare the priority (of the source file)
                         * and the line number.
                         *
                         * For v2 data: we rely on the fact that the filenames in the hwdb
                         * are added in the order of priority (higher later), because they
                         * are *processed* in the order of priority. So we compare the
                         * indices to determine which file had higher priority. Comparing
                         * the strings alphabetically would be useless, because those are
                         * full paths, and e.g. /usr/lib would sort after /etc, even
                         * though it has lower priority. This is not reliable because of
                         * suffix compression, but should work for the most common case of
                         * /usr/lib/udev/hwbd.d and /etc/udev/hwdb.d, and is better than
                         * not doing the comparison at all.
                         */
                        bool lower;

                        if (entry2->file_priority == 0)
                                lower = entry2->filename_off < old->filename_off ||
                                        (entry2->filename_off == old->filename_off && entry2->line_number < old->line_number);
                        else
                                lower = entry2->file_priority < old->file_priority ||
                                        (entry2->file_priority == old->file_priority && entry2->line_number < old->line_number);
                        if (lower)
                                return 0;
                }
        }

        r = ordered_hashmap_ensure_allocated(&hwdb->properties, &string_hash_ops);
        if (r < 0)
                return r;

        r = ordered_hashmap_replace(hwdb->properties, key, (void *)entry);
        if (r < 0)
                return r;

        hwdb->properties_modified = true;

        return 0;
}

static int trie_fnmatch_f(sd_hwdb *hwdb, const struct trie_node_f *node, size_t p,
                          struct linebuf *buf, const char *search) {
        size_t len;
        size_t i;
        const char *prefix;
        int err;

        prefix = trie_string(hwdb, node->prefix_off);
        len = strlen(prefix + p);
        linebuf_add(buf, prefix + p, len);

        for (i = 0; i < node->children_count; i++) {
                const struct trie_child_entry_f *child = trie_node_child(hwdb, node, i);

                linebuf_add_char(buf, child->c);
                err = trie_fnmatch_f(hwdb, trie_node_from_off(hwdb, child->child_off), 0, buf, search);
                if (err < 0)
                        return err;
                linebuf_rem_char(buf);
        }

        if (le64toh(node->values_count) && fnmatch(linebuf_get(buf), search, 0) == 0)
                for (i = 0; i < le64toh(node->values_count); i++) {
                        err = hwdb_add_property(hwdb, trie_node_value(hwdb, node, i));
                        if (err < 0)
                                return err;
                }

        linebuf_rem(buf, len);
        return 0;
}

static int trie_search_f(sd_hwdb *hwdb, const char *search) {
        struct linebuf buf;
        const struct trie_node_f *node;
        size_t i = 0;
        int err;

        linebuf_init(&buf);

        node = trie_node_from_off(hwdb, hwdb->head->nodes_root_off);
        while (node) {
                const struct trie_node_f *child;
                size_t p = 0;

                if (node->prefix_off) {
                        uint8_t c;

                        for (; (c = trie_string(hwdb, node->prefix_off)[p]); p++) {
                                if (IN_SET(c, '*', '?', '['))
                                        return trie_fnmatch_f(hwdb, node, p, &buf, search + i + p);
                                if (c != search[i + p])
                                        return 0;
                        }
                        i += p;
                }

                child = node_lookup_f(hwdb, node, '*');
                if (child) {
                        linebuf_add_char(&buf, '*');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(hwdb, node, '?');
                if (child) {
                        linebuf_add_char(&buf, '?');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(hwdb, node, '[');
                if (child) {
                        linebuf_add_char(&buf, '[');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                if (search[i] == '\0') {
                        size_t n;

                        for (n = 0; n < le64toh(node->values_count); n++) {
                                err = hwdb_add_property(hwdb, trie_node_value(hwdb, node, n));
                                if (err < 0)
                                        return err;
                        }
                        return 0;
                }

                child = node_lookup_f(hwdb, node, search[i]);
                node = child;
                i++;
        }
        return 0;
}

static const char hwdb_bin_paths[] =
        "/etc/systemd/hwdb/hwdb.bin\0"
        "/etc/udev/hwdb.bin\0"
        "/usr/lib/systemd/hwdb/hwdb.bin\0"
#if HAVE_SPLIT_USR
        "/lib/systemd/hwdb/hwdb.bin\0"
#endif
        UDEVLIBEXECDIR "/hwdb.bin\0";

_public_ int sd_hwdb_new(sd_hwdb **ret) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char *hwdb_bin_path;
        const char sig[] = HWDB_SIG;

        assert_return(ret, -EINVAL);

        hwdb = new0(sd_hwdb, 1);
        if (!hwdb)
                return -ENOMEM;

        hwdb->n_ref = REFCNT_INIT;

        /* find hwdb.bin in hwdb_bin_paths */
        NULSTR_FOREACH(hwdb_bin_path, hwdb_bin_paths) {
                hwdb->f = fopen(hwdb_bin_path, "re");
                if (hwdb->f)
                        break;
                else if (errno == ENOENT)
                        continue;
                else
                        return log_debug_errno(errno, "Failed to open %s: %m", hwdb_bin_path);
        }

        if (!hwdb->f) {
                log_debug("hwdb.bin does not exist, please run 'systemd-hwdb update'");
                return -ENOENT;
        }

        if (fstat(fileno(hwdb->f), &hwdb->st) < 0 ||
            (size_t) hwdb->st.st_size < offsetof(struct trie_header_f, strings_len) + 8)
                return log_debug_errno(errno, "Failed to read %s: %m", hwdb_bin_path);

        hwdb->map = mmap(0, hwdb->st.st_size, PROT_READ, MAP_SHARED, fileno(hwdb->f), 0);
        if (hwdb->map == MAP_FAILED)
                return log_debug_errno(errno, "Failed to map %s: %m", hwdb_bin_path);

        if (memcmp(hwdb->map, sig, sizeof(hwdb->head->signature)) != 0 ||
            (size_t) hwdb->st.st_size != le64toh(hwdb->head->file_size)) {
                log_debug("Failed to recognize the format of %s", hwdb_bin_path);
                return -EINVAL;
        }

        log_debug("=== trie on-disk ===");
        log_debug("tool version:          %"PRIu64, le64toh(hwdb->head->tool_version));
        log_debug("file size:        %8"PRIi64" bytes", hwdb->st.st_size);
        log_debug("header size       %8"PRIu64" bytes", le64toh(hwdb->head->header_size));
        log_debug("strings           %8"PRIu64" bytes", le64toh(hwdb->head->strings_len));
        log_debug("nodes             %8"PRIu64" bytes", le64toh(hwdb->head->nodes_len));

        *ret = TAKE_PTR(hwdb);

        return 0;
}

static sd_hwdb *hwdb_free(sd_hwdb *hwdb) {
        assert(hwdb);

        if (hwdb->map)
                munmap((void *)hwdb->map, hwdb->st.st_size);
        safe_fclose(hwdb->f);
        ordered_hashmap_free(hwdb->properties);
        return mfree(hwdb);
}

DEFINE_PUBLIC_ATOMIC_REF_UNREF_FUNC(sd_hwdb, sd_hwdb, hwdb_free)

bool hwdb_validate(sd_hwdb *hwdb) {
        bool found = false;
        const char* p;
        struct stat st;

        if (!hwdb)
                return false;
        if (!hwdb->f)
                return false;

        /* if hwdb.bin doesn't exist anywhere, we need to update */
        NULSTR_FOREACH(p, hwdb_bin_paths) {
                if (stat(p, &st) >= 0) {
                        found = true;
                        break;
                }
        }
        if (!found)
                return true;

        if (timespec_load(&hwdb->st.st_mtim) != timespec_load(&st.st_mtim))
                return true;
        return false;
}

static int properties_prepare(sd_hwdb *hwdb, const char *modalias) {
        assert(hwdb);
        assert(modalias);

        ordered_hashmap_clear(hwdb->properties);
        hwdb->properties_modified = true;

        return trie_search_f(hwdb, modalias);
}

_public_ int sd_hwdb_get(sd_hwdb *hwdb, const char *modalias, const char *key, const char **_value) {
        const struct trie_value_entry_f *entry;
        int r;

        assert_return(hwdb, -EINVAL);
        assert_return(hwdb->f, -EINVAL);
        assert_return(modalias, -EINVAL);
        assert_return(_value, -EINVAL);

        r = properties_prepare(hwdb, modalias);
        if (r < 0)
                return r;

        entry = ordered_hashmap_get(hwdb->properties, key);
        if (!entry)
                return -ENOENT;

        *_value = trie_string(hwdb, entry->value_off);

        return 0;
}

_public_ int sd_hwdb_seek(sd_hwdb *hwdb, const char *modalias) {
        int r;

        assert_return(hwdb, -EINVAL);
        assert_return(hwdb->f, -EINVAL);
        assert_return(modalias, -EINVAL);

        r = properties_prepare(hwdb, modalias);
        if (r < 0)
                return r;

        hwdb->properties_modified = false;
        hwdb->properties_iterator = ITERATOR_FIRST;

        return 0;
}

_public_ int sd_hwdb_enumerate(sd_hwdb *hwdb, const char **key, const char **value) {
        const struct trie_value_entry_f *entry;
        const void *k;

        assert_return(hwdb, -EINVAL);
        assert_return(key, -EINVAL);
        assert_return(value, -EINVAL);

        if (hwdb->properties_modified)
                return -EAGAIN;

        ordered_hashmap_iterate(hwdb->properties, &hwdb->properties_iterator, (void **)&entry, &k);
        if (!k)
                return 0;

        *key = k;
        *value = trie_string(hwdb, entry->value_off);

        return 1;
}
