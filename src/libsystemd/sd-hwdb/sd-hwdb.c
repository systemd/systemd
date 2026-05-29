/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2008 Alan Jenkins <alan.christopher.jenkins@googlemail.com>
***/

#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "sd-hwdb.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "hwdb-internal.h"
#include "log.h"
#include "nulstr-util.h"
#include "string-util.h"

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

static const void* hwdb_at(sd_hwdb *hwdb, uint64_t off, uint64_t size) {
        assert(hwdb);

        uint64_t file_size = hwdb->st.st_size;

        /* off == file_size is rejected too: a read at EOF is always OOB, and this keeps the
         * boundary unambiguous even for a size == 0 caller (which would otherwise get a
         * one-past-the-end pointer). */
        if (off >= file_size)
                return NULL;
        if (file_size - off < size)
                return NULL;

        return (const uint8_t*) hwdb->map + off;
}

static const struct trie_node_f* trie_node_from_off(sd_hwdb *hwdb, le64_t off) {
        assert(hwdb);
        assert(hwdb->head);

        uint64_t offset = le64toh(off);
        uint64_t node_size = le64toh(hwdb->head->node_size);
        uint64_t child_entry_size = le64toh(hwdb->head->child_entry_size);
        uint64_t value_entry_size = le64toh(hwdb->head->value_entry_size);

        if (node_size < sizeof(struct trie_node_f))
                return NULL;
        if (child_entry_size < sizeof(struct trie_child_entry_f))
                return NULL;
        if (value_entry_size < sizeof(struct trie_value_entry_f))
                return NULL;

        const struct trie_node_f *node = hwdb_at(hwdb, offset, node_size);
        if (!node)
                return NULL;

        uint64_t children_bytes, values_bytes, total;
        if (!MUL_SAFE(&children_bytes, (uint64_t) node->children_count, child_entry_size))
                return NULL;
        if (!MUL_SAFE(&values_bytes, le64toh(node->values_count), value_entry_size))
                return NULL;
        if (!ADD_SAFE(&total, node_size, children_bytes))
                return NULL;
        if (!INC_SAFE(&total, values_bytes))
                return NULL;

        if (!hwdb_at(hwdb, offset, total))
                return NULL;

        return node;
}

static const char* trie_string(sd_hwdb *hwdb, le64_t off) {
        assert(hwdb);

        uint64_t file_size = hwdb->st.st_size;
        uint64_t offset = le64toh(off);

        const char *p = hwdb_at(hwdb, offset, /* size= */ 1);
        if (!p)
                return NULL;

        /* Clamp to SIZE_MAX so memchr()'s size_t arg cannot truncate on 32-bit. */
        size_t avail = (size_t) MIN(file_size - offset, (uint64_t) SIZE_MAX);
        if (!memchr(p, '\0', avail))
                return NULL;

        return p;
}

static int trie_children_cmp_f(const void *v1, const void *v2) {
        const struct trie_child_entry_f *n1 = v1;
        const struct trie_child_entry_f *n2 = v2;

        return n1->c - n2->c;
}

static const struct trie_node_f *node_lookup_f(sd_hwdb *hwdb, const struct trie_node_f *node, uint8_t c) {
        const struct trie_child_entry_f *child;
        struct trie_child_entry_f search;

        search.c = c;
        child = bsearch(&search, (const char *)node + le64toh(hwdb->head->node_size), node->children_count,
                        le64toh(hwdb->head->child_entry_size), trie_children_cmp_f);
        if (child)
                /* Treat corrupt child offsets like lookup misses. */
                return trie_node_from_off(hwdb, child->child_off);

        return NULL;
}

static int hwdb_add_property(sd_hwdb *hwdb, const struct trie_value_entry_f *entry) {
        const char *key;
        int r;

        assert(hwdb);

        key = trie_string(hwdb, entry->key_off);
        if (!key)
                return -EBADMSG;

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

        r = ordered_hashmap_ensure_replace(&hwdb->properties, &string_hash_ops, key, (void *) entry);
        if (r < 0)
                return r;

        hwdb->properties_modified = true;

        return 0;
}

/* Cap recursion depth so a corrupt hwdb.bin whose children offsets form a
 * cycle (or just a deep linear chain) cannot exhaust the stack. Real-world
 * hwdb files do not approach this; the deepest legitimate trie key is well
 * under a kilobyte. */
#define HWDB_RECURSION_MAX 2048U

static int trie_fnmatch_f(sd_hwdb *hwdb, const struct trie_node_f *node, size_t p,
                          struct linebuf *buf, const char *search, unsigned depth) {
        size_t len;
        size_t i;
        const char *prefix;
        int err;

        assert(hwdb);
        assert(node);

        if (depth >= HWDB_RECURSION_MAX)
                return -EBADMSG;

        prefix = trie_string(hwdb, node->prefix_off);
        if (!prefix)
                return -EBADMSG;

        len = strlen(prefix);
        if (p > len)
                return -EBADMSG;
        len -= p;

        if (!linebuf_add(buf, prefix + p, len))
                return -EINVAL;

        for (i = 0; i < node->children_count; i++) {
                const struct trie_child_entry_f *child = trie_node_child(hwdb, node, i);
                const struct trie_node_f *child_node;

                linebuf_add_char(buf, child->c);
                child_node = trie_node_from_off(hwdb, child->child_off);
                if (!child_node)
                        return -EBADMSG;

                err = trie_fnmatch_f(hwdb, child_node, 0, buf, search, depth + 1);
                if (err < 0)
                        return err;
                linebuf_rem_char(buf);
        }

        if (le64toh(node->values_count) != 0) {
                const char *line = linebuf_get(buf);
                if (!line)
                        return -EBADMSG;

                if (fnmatch(line, search, 0) == 0)
                        for (i = 0; i < le64toh(node->values_count); i++) {
                                err = hwdb_add_property(hwdb, trie_node_value(hwdb, node, i));
                                if (err < 0)
                                        return err;
                        }
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
        if (!node)
                return -EBADMSG;

        while (node) {
                const struct trie_node_f *child;
                size_t p = 0;

                if (node->prefix_off) {
                        const char *prefix;
                        char c;

                        prefix = trie_string(hwdb, node->prefix_off);
                        if (!prefix)
                                return -EBADMSG;

                        for (; (c = prefix[p]); p++) {
                                if (IN_SET(c, '*', '?', '['))
                                        return trie_fnmatch_f(hwdb, node, p, &buf, search + i + p, 0);
                                if (c != search[i + p])
                                        return 0;
                        }
                        i += p;
                }

                child = node_lookup_f(hwdb, node, '*');
                if (child) {
                        linebuf_add_char(&buf, '*');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i, 0);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(hwdb, node, '?');
                if (child) {
                        linebuf_add_char(&buf, '?');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i, 0);
                        if (err < 0)
                                return err;
                        linebuf_rem_char(&buf);
                }

                child = node_lookup_f(hwdb, node, '[');
                if (child) {
                        linebuf_add_char(&buf, '[');
                        err = trie_fnmatch_f(hwdb, child, 0, &buf, search + i, 0);
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

static int hwdb_new(const char *path, sd_hwdb **ret) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char sig[] = HWDB_SIG;

        assert_return(ret, -EINVAL);

        hwdb = new0(sd_hwdb, 1);
        if (!hwdb)
                return -ENOMEM;

        hwdb->n_ref = 1;

        /* Find hwdb.bin in the explicit path if provided, or iterate over HWDB_BIN_PATHS otherwise  */
        if (!isempty(path)) {
                log_debug("Trying to open \"%s\"...", path);
                hwdb->f = fopen(path, "re");
                if (!hwdb->f)
                        return log_debug_errno(errno, "Failed to open %s: %m", path);
        } else {
                NULSTR_FOREACH(p, HWDB_BIN_PATHS) {
                        log_debug("Trying to open \"%s\"...", p);
                        hwdb->f = fopen(p, "re");
                        if (hwdb->f) {
                                path = p;
                                break;
                        }
                        if (errno != ENOENT)
                                return log_debug_errno(errno, "Failed to open %s: %m", p);
                }

                if (!hwdb->f)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "hwdb.bin does not exist, please run 'systemd-hwdb update'.");
        }

        if (fstat(fileno(hwdb->f), &hwdb->st) < 0)
                return log_debug_errno(errno, "Failed to stat %s: %m", path);
        if (hwdb->st.st_size < (off_t) offsetof(struct trie_header_f, strings_len) + 8)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO), "File %s is too short.", path);
        if (file_offset_beyond_memory_size(hwdb->st.st_size))
                return log_debug_errno(SYNTHETIC_ERRNO(EFBIG), "File %s is too long.", path);

        hwdb->map = mmap(NULL, hwdb->st.st_size, PROT_READ, MAP_SHARED, fileno(hwdb->f), 0);
        if (hwdb->map == MAP_FAILED)
                return log_debug_errno(errno, "Failed to map %s: %m", path);

        if (memcmp(hwdb->map, sig, sizeof(hwdb->head->signature)) != 0 ||
            (size_t) hwdb->st.st_size != le64toh(hwdb->head->file_size))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to recognize the format of %s.", path);

        log_debug("=== trie on-disk ===");
        log_debug("tool version:          %"PRIu64, le64toh(hwdb->head->tool_version));
        log_debug("file size:        %8"PRIi64" bytes", hwdb->st.st_size);
        log_debug("header size       %8"PRIu64" bytes", le64toh(hwdb->head->header_size));
        log_debug("strings           %8"PRIu64" bytes", le64toh(hwdb->head->strings_len));
        log_debug("nodes             %8"PRIu64" bytes", le64toh(hwdb->head->nodes_len));

        *ret = TAKE_PTR(hwdb);

        return 0;
}

_public_ int sd_hwdb_new_from_path(const char *path, sd_hwdb **ret) {
        assert_return(!isempty(path), -EINVAL);

        return hwdb_new(path, ret);
}

_public_ int sd_hwdb_new(sd_hwdb **ret) {
        return hwdb_new(NULL, ret);
}

static sd_hwdb *hwdb_free(sd_hwdb *hwdb) {
        assert(hwdb);

        if (hwdb->map)
                munmap((void *)hwdb->map, hwdb->st.st_size);
        safe_fclose(hwdb->f);
        ordered_hashmap_free(hwdb->properties);
        return mfree(hwdb);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_hwdb, sd_hwdb, hwdb_free)

static int properties_prepare(sd_hwdb *hwdb, const char *modalias) {
        assert(hwdb);
        assert(modalias);

        ordered_hashmap_clear(hwdb->properties);
        hwdb->properties_modified = true;

        return trie_search_f(hwdb, modalias);
}

_public_ int sd_hwdb_get(sd_hwdb *hwdb, const char *modalias, const char *key, const char **ret) {
        const struct trie_value_entry_f *entry;
        const char *value;
        int r;

        assert_return(hwdb, -EINVAL);
        assert_return(hwdb->f, -EINVAL);
        assert_return(modalias, -EINVAL);
        assert_return(ret, -EINVAL);

        r = properties_prepare(hwdb, modalias);
        if (r < 0)
                return r;

        entry = ordered_hashmap_get(hwdb->properties, key);
        if (!entry)
                return -ENOENT;

        value = trie_string(hwdb, entry->value_off);
        if (!value)
                return -EBADMSG;

        *ret = value;

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

_public_ int sd_hwdb_enumerate(sd_hwdb *hwdb, const char **ret_key, const char **ret_value) {
        const struct trie_value_entry_f *entry;
        const char *v;
        const void *k;

        assert_return(hwdb, -EINVAL);
        assert_return(ret_key, -EINVAL);
        assert_return(ret_value, -EINVAL);

        if (hwdb->properties_modified)
                return -EAGAIN;

        if (!ordered_hashmap_iterate(hwdb->properties, &hwdb->properties_iterator, (void **)&entry, &k))
                return 0;

        v = trie_string(hwdb, entry->value_off);
        if (!v)
                return -EBADMSG;

        *ret_key = k;
        *ret_value = v;

        return 1;
}
