/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <stdio.h>
#include <sys/stat.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hwdb-internal.h"
#include "hwdb-util.h"
#include "label-util.h"
#include "mkdir-label.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "sort-util.h"
#include "strbuf.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"

static const char* const conf_file_dirs[] = {
        "/etc/udev/hwdb.d",
        UDEVLIBEXECDIR "/hwdb.d",
        NULL
};

/*
 * Generic udev properties, key-value database based on modalias strings.
 * Uses a Patricia/radix trie to index all matches for efficient lookup.
 */

/* in-memory trie objects */
struct trie {
        struct trie_node *root;
        struct strbuf *strings;

        size_t nodes_count;
        size_t children_count;
        size_t values_count;
};

struct trie_node {
        /* prefix, common part for all children of this node */
        size_t prefix_off;

        /* sorted array of pointers to children nodes */
        struct trie_child_entry *children;
        uint8_t children_count;

        /* sorted array of key-value pairs */
        struct trie_value_entry *values;
        size_t values_count;
};

/* children array item with char (0-255) index */
struct trie_child_entry {
        uint8_t c;
        struct trie_node *child;
};

/* value array item with key-value pairs */
struct trie_value_entry {
        size_t key_off;
        size_t value_off;
        size_t filename_off;
        uint32_t line_number;
        uint16_t file_priority;
};

static int trie_children_cmp(const struct trie_child_entry *a, const struct trie_child_entry *b) {
        return CMP(a->c, b->c);
}

static int node_add_child(struct trie *trie, struct trie_node *node, struct trie_node *node_child, uint8_t c) {
        struct trie_child_entry *child;

        /* extend array, add new entry, sort for bisection */
        child = reallocarray(node->children, node->children_count + 1, sizeof(struct trie_child_entry));
        if (!child)
                return -ENOMEM;

        node->children = child;
        trie->children_count++;
        node->children[node->children_count].c = c;
        node->children[node->children_count].child = node_child;
        node->children_count++;
        typesafe_qsort(node->children, node->children_count, trie_children_cmp);
        trie->nodes_count++;

        return 0;
}

static struct trie_node *node_lookup(const struct trie_node *node, uint8_t c) {
        struct trie_child_entry *child;
        struct trie_child_entry search;

        search.c = c;
        child = typesafe_bsearch(&search, node->children, node->children_count, trie_children_cmp);
        if (child)
                return child->child;
        return NULL;
}

static void trie_node_cleanup(struct trie_node *node) {
        if (!node)
                return;

        for (size_t i = 0; i < node->children_count; i++)
                trie_node_cleanup(node->children[i].child);
        free(node->children);
        free(node->values);
        free(node);
}

static struct trie* trie_free(struct trie *trie) {
        if (!trie)
                return NULL;

        trie_node_cleanup(trie->root);
        strbuf_free(trie->strings);
        return mfree(trie);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct trie*, trie_free);

static int trie_values_cmp(const struct trie_value_entry *a, const struct trie_value_entry *b, struct trie *trie) {
        return strcmp(trie->strings->buf + a->key_off,
                      trie->strings->buf + b->key_off);
}

static int trie_node_add_value(struct trie *trie, struct trie_node *node,
                               const char *key, const char *value,
                               const char *filename, uint16_t file_priority, uint32_t line_number, bool compat) {
        ssize_t k, v, fn = 0;
        struct trie_value_entry *val;

        k = strbuf_add_string(trie->strings, key, strlen(key));
        if (k < 0)
                return k;
        v = strbuf_add_string(trie->strings, value, strlen(value));
        if (v < 0)
                return v;

        if (!compat) {
                fn = strbuf_add_string(trie->strings, filename, strlen(filename));
                if (fn < 0)
                        return fn;
        }

        if (node->values_count) {
                struct trie_value_entry search = {
                        .key_off = k,
                        .value_off = v,
                };

                val = typesafe_bsearch_r(&search, node->values, node->values_count, trie_values_cmp, trie);
                if (val) {
                        /* At this point we have 2 identical properties on the same match-string.
                         * Since we process files in order, we just replace the previous value. */
                        val->value_off = v;
                        val->filename_off = fn;
                        val->file_priority = file_priority;
                        val->line_number = line_number;
                        return 0;
                }
        }

        /* extend array, add new entry, sort for bisection */
        val = reallocarray(node->values, node->values_count + 1, sizeof(struct trie_value_entry));
        if (!val)
                return -ENOMEM;
        trie->values_count++;
        node->values = val;
        node->values[node->values_count] = (struct trie_value_entry) {
                .key_off = k,
                .value_off = v,
                .filename_off = fn,
                .file_priority = file_priority,
                .line_number = line_number,
        };
        node->values_count++;
        typesafe_qsort_r(node->values, node->values_count, trie_values_cmp, trie);
        return 0;
}

static int trie_insert(struct trie *trie, struct trie_node *node, const char *search,
                       const char *key, const char *value,
                       const char *filename, uint16_t file_priority, uint32_t line_number, bool compat) {
        int r = 0;

        for (size_t i = 0;; i++) {
                size_t p;
                char c;
                struct trie_node *child;

                for (p = 0; (c = trie->strings->buf[node->prefix_off + p]); p++) {
                        _cleanup_free_ struct trie_node *new_child = NULL;
                        _cleanup_free_ char *s = NULL;
                        ssize_t off;

                        if (c == search[i + p])
                                continue;

                        /* split node */
                        new_child = new(struct trie_node, 1);
                        if (!new_child)
                                return -ENOMEM;

                        /* move values from parent to child */
                        *new_child = (struct trie_node) {
                                .prefix_off = node->prefix_off + p+1,
                                .children = node->children,
                                .children_count = node->children_count,
                                .values = node->values,
                                .values_count = node->values_count,
                        };

                        /* update parent; use strdup() because the source gets realloc()d */
                        s = strndup(trie->strings->buf + node->prefix_off, p);
                        if (!s)
                                return -ENOMEM;

                        off = strbuf_add_string(trie->strings, s, p);
                        if (off < 0)
                                return off;

                        *node = (struct trie_node) {
                                .prefix_off = off,
                        };
                        r = node_add_child(trie, node, new_child, c);
                        if (r < 0)
                                return r;

                        new_child = NULL; /* avoid cleanup */
                        break;
                }
                i += p;

                c = search[i];
                if (c == '\0')
                        return trie_node_add_value(trie, node, key, value, filename, file_priority, line_number, compat);

                child = node_lookup(node, c);
                if (!child) {
                        _cleanup_free_ struct trie_node *new_child = NULL;
                        ssize_t off;

                        /* new child */
                        new_child = new(struct trie_node, 1);
                        if (!new_child)
                                return -ENOMEM;

                        off = strbuf_add_string(trie->strings, search + i+1, strlen(search + i+1));
                        if (off < 0)
                                return off;

                        *new_child = (struct trie_node) {
                                .prefix_off = off,
                        };

                        r = node_add_child(trie, node, new_child, c);
                        if (r < 0)
                                return r;

                        child = TAKE_PTR(new_child);
                        return trie_node_add_value(trie, child, key, value, filename, file_priority, line_number, compat);
                }

                node = child;
        }
}

struct trie_f {
        struct trie *trie;
        uint64_t strings_off;

        uint64_t nodes_count;
        uint64_t children_count;
        uint64_t values_count;
};

/* calculate the storage space for the nodes, children arrays, value arrays */
static void trie_store_nodes_size(struct trie_f *trie, struct trie_node *node, bool compat) {
        for (uint64_t i = 0; i < node->children_count; i++)
                trie_store_nodes_size(trie, node->children[i].child, compat);

        trie->strings_off += sizeof(struct trie_node_f);
        for (uint64_t i = 0; i < node->children_count; i++)
                trie->strings_off += sizeof(struct trie_child_entry_f);
        for (uint64_t i = 0; i < node->values_count; i++)
                trie->strings_off += compat ? sizeof(struct trie_value_entry_f) : sizeof(struct trie_value_entry2_f);
}

static int64_t trie_store_nodes(struct trie_f *trie, FILE *f, struct trie_node *node, bool compat) {
        _cleanup_free_ struct trie_child_entry_f *children = NULL;
        int64_t node_off;

        assert(trie);
        assert(f);
        assert(node);

        if (node->children_count) {
                children = new(struct trie_child_entry_f, node->children_count);
                if (!children)
                        return -ENOMEM;
        }

        /* post-order recursion */
        for (uint64_t i = 0; i < node->children_count; i++) {
                int64_t child_off;

                child_off = trie_store_nodes(trie, f, node->children[i].child, compat);
                if (child_off < 0)
                        return child_off;

                children[i] = (struct trie_child_entry_f) {
                        .c = node->children[i].c,
                        .child_off = htole64(child_off),
                };
        }

        struct trie_node_f n = {
                .prefix_off = htole64(trie->strings_off + node->prefix_off),
                .children_count = node->children_count,
                .values_count = htole64(node->values_count),
        };

        /* write node */
        node_off = ftello(f);
        fwrite(&n, sizeof(struct trie_node_f), 1, f);
        trie->nodes_count++;

        /* append children array */
        if (node->children_count) {
                fwrite(children, sizeof(struct trie_child_entry_f), node->children_count, f);
                trie->children_count += node->children_count;
        }

        /* append values array */
        for (uint64_t i = 0; i < node->values_count; i++) {
                struct trie_value_entry2_f v = {
                        .key_off = htole64(trie->strings_off + node->values[i].key_off),
                        .value_off = htole64(trie->strings_off + node->values[i].value_off),
                        .filename_off = htole64(trie->strings_off + node->values[i].filename_off),
                        .line_number = htole32(node->values[i].line_number),
                        .file_priority = htole16(node->values[i].file_priority),
                };

                fwrite(&v, compat ? sizeof(struct trie_value_entry_f) : sizeof(struct trie_value_entry2_f), 1, f);
        }
        trie->values_count += node->values_count;

        return node_off;
}

static int trie_store(struct trie *trie, const char *filename, bool compat) {
        struct trie_f t = {
                .trie = trie,
                .strings_off = sizeof(struct trie_header_f),
        };
        _cleanup_(unlink_and_freep) char *filename_tmp = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int64_t pos, root_off, size;
        int r;

        assert(trie);
        assert(filename);

        /* calculate size of header, nodes, children entries, value entries */
        trie_store_nodes_size(&t, trie->root, compat);

        r = fopen_tmpfile_linkable(filename, O_WRONLY|O_CLOEXEC, &filename_tmp, &f);
        if (r < 0)
                return r;

        if (fchmod(fileno(f), 0444) < 0)
                return -errno;

        struct trie_header_f h = {
                .signature = HWDB_SIG,
                .tool_version = htole64(PROJECT_VERSION),
                .header_size = htole64(sizeof(struct trie_header_f)),
                .node_size = htole64(sizeof(struct trie_node_f)),
                .child_entry_size = htole64(sizeof(struct trie_child_entry_f)),
                .value_entry_size = htole64(compat ? sizeof(struct trie_value_entry_f) : sizeof(struct trie_value_entry2_f)),
        };

        /* write nodes */
        if (fseeko(f, sizeof(struct trie_header_f), SEEK_SET) < 0)
                return -errno;

        root_off = trie_store_nodes(&t, f, trie->root, compat);
        h.nodes_root_off = htole64(root_off);
        pos = ftello(f);
        h.nodes_len = htole64(pos - sizeof(struct trie_header_f));

        /* write string buffer */
        fwrite(trie->strings->buf, trie->strings->len, 1, f);
        h.strings_len = htole64(trie->strings->len);

        /* write header */
        size = ftello(f);
        h.file_size = htole64(size);
        if (fseeko(f, 0, SEEK_SET) < 0)
                return -errno;
        fwrite(&h, sizeof(struct trie_header_f), 1, f);

        r = flink_tmpfile(f, filename_tmp, filename, LINK_TMPFILE_REPLACE|LINK_TMPFILE_SYNC);
        if (r < 0)
                return r;

        /* write succeeded */

        log_debug("=== trie on-disk ===");
        log_debug("size:             %8"PRIi64" bytes", size);
        log_debug("header:           %8zu bytes", sizeof(struct trie_header_f));
        log_debug("nodes:            %8"PRIu64" bytes (%8"PRIu64")",
                  t.nodes_count * sizeof(struct trie_node_f), t.nodes_count);
        log_debug("child pointers:   %8"PRIu64" bytes (%8"PRIu64")",
                  t.children_count * sizeof(struct trie_child_entry_f), t.children_count);
        log_debug("value pointers:   %8"PRIu64" bytes (%8"PRIu64")",
                  t.values_count * (compat ? sizeof(struct trie_value_entry_f) : sizeof(struct trie_value_entry2_f)), t.values_count);
        log_debug("string store:     %8zu bytes", trie->strings->len);
        log_debug("strings start:    %8"PRIu64, t.strings_off);
        return 0;
}

static int insert_data(struct trie *trie, char **match_list, char *line, const char *filename,
                       uint16_t file_priority, uint32_t line_number, bool compat) {
        char *value;

        assert(line[0] == ' ');

        value = strchr(line, '=');
        if (!value)
                return log_syntax(NULL, LOG_WARNING, filename, line_number, SYNTHETIC_ERRNO(EINVAL),
                                  "Key-value pair expected but got \"%s\", ignoring.", line);

        value[0] = '\0';
        value++;

        /* Replace multiple leading spaces by a single space */
        while (isblank(line[0]) && isblank(line[1]))
                line++;

        if (isempty(line + 1))
                return log_syntax(NULL, LOG_WARNING, filename, line_number, SYNTHETIC_ERRNO(EINVAL),
                                  "Empty key in \"%s=%s\", ignoring.",
                                  line, value);

        STRV_FOREACH(entry, match_list)
                trie_insert(trie, trie->root, *entry, line, value, filename, file_priority, line_number, compat);

        return 0;
}

static int import_file(struct trie *trie, const char *filename, uint16_t file_priority, bool compat) {
        enum {
                HW_NONE,
                HW_MATCH,
                HW_DATA,
        } state = HW_NONE;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_strv_free_ char **match_list = NULL;
        uint32_t line_number = 0;
        int r, err;

        f = fopen(filename, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                size_t len;
                char *pos;

                r = read_line_full(f, LONG_LINE_MAX, READ_LINE_NOT_A_TTY, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                line_number ++;

                /* comment line */
                if (line[0] == '#')
                        continue;

                /* strip trailing comment */
                pos = strchr(line, '#');
                if (pos)
                        pos[0] = '\0';

                /* strip trailing whitespace */
                len = strlen(line);
                while (len > 0 && isspace(line[len-1]))
                        len--;
                line[len] = '\0';

                switch (state) {
                case HW_NONE:
                        if (len == 0)
                                break;

                        if (line[0] == ' ') {
                                r = log_syntax(NULL, LOG_WARNING, filename, line_number, SYNTHETIC_ERRNO(EINVAL),
                                               "Match expected but got indented property \"%s\", ignoring line.", line);
                                break;
                        }

                        /* start of record, first match */
                        state = HW_MATCH;

                        err = strv_extend(&match_list, line);
                        if (err < 0)
                                return err;

                        break;

                case HW_MATCH:
                        if (len == 0) {
                                r = log_syntax(NULL, LOG_WARNING, filename, line_number, SYNTHETIC_ERRNO(EINVAL),
                                               "Property expected, ignoring record with no properties.");
                                state = HW_NONE;
                                match_list = strv_free(match_list);
                                break;
                        }

                        if (line[0] != ' ') {
                                /* another match */
                                err = strv_extend(&match_list, line);
                                if (err < 0)
                                        return err;

                                break;
                        }

                        /* first data */
                        state = HW_DATA;
                        err = insert_data(trie, match_list, line, filename, file_priority, line_number, compat);
                        if (err < 0)
                                r = err;
                        break;

                case HW_DATA:
                        if (len == 0) {
                                /* end of record */
                                state = HW_NONE;
                                match_list = strv_free(match_list);
                                break;
                        }

                        if (line[0] != ' ') {
                                r = log_syntax(NULL, LOG_WARNING, filename, line_number, SYNTHETIC_ERRNO(EINVAL),
                                               "Property or empty line expected, got \"%s\", ignoring record.", line);
                                state = HW_NONE;
                                match_list = strv_free(match_list);
                                break;
                        }

                        err = insert_data(trie, match_list, line, filename, file_priority, line_number, compat);
                        if (err < 0)
                                r = err;
                        break;
                };
        }

        if (state == HW_MATCH)
                log_syntax(NULL, LOG_WARNING, filename, line_number, 0,
                           "Property expected, ignoring record with no properties.");

        return r;
}

int hwdb_update(const char *root, const char *hwdb_bin_dir, bool strict, bool compat) {
        _cleanup_free_ char *hwdb_bin = NULL;
        _cleanup_(trie_freep) struct trie *trie = NULL;
        _cleanup_strv_free_ char **files = NULL;
        uint16_t file_priority = 1;
        int r = 0, err;

        /* The argument 'compat' controls the format version of database. If false, then hwdb.bin will be
         * created with additional information such that priority, line number, and filename of database
         * source. If true, then hwdb.bin will be created without the information. systemd-hwdb command
         * should set the argument false, and 'udevadm hwdb' command should set it true. */

        hwdb_bin = path_join(root, hwdb_bin_dir ?: "/etc/udev", "hwdb.bin");
        if (!hwdb_bin)
                return -ENOMEM;

        trie = new0(struct trie, 1);
        if (!trie)
                return -ENOMEM;

        /* string store */
        trie->strings = strbuf_new();
        if (!trie->strings)
                return -ENOMEM;

        /* index */
        trie->root = new0(struct trie_node, 1);
        if (!trie->root)
                return -ENOMEM;

        trie->nodes_count++;

        err = conf_files_list_strv(&files, ".hwdb", root, 0, conf_file_dirs);
        if (err < 0)
                return log_error_errno(err, "Failed to enumerate hwdb files: %m");

        if (strv_isempty(files)) {
                if (unlink(hwdb_bin) < 0) {
                        if (errno != ENOENT)
                                return log_error_errno(errno, "Failed to remove compiled hwdb database %s: %m", hwdb_bin);

                        log_info("No hwdb files found, skipping.");
                } else
                        log_info("No hwdb files found, compiled hwdb database %s removed.", hwdb_bin);

                return 0;
        }

        STRV_FOREACH(f, files) {
                log_debug("Reading file \"%s\"", *f);
                err = import_file(trie, *f, file_priority++, compat);
                if (err < 0 && strict)
                        r = err;
        }

        strbuf_complete(trie->strings);

        log_debug("=== trie in-memory ===");
        log_debug("nodes:            %8zu bytes (%8zu)",
                  trie->nodes_count * sizeof(struct trie_node), trie->nodes_count);
        log_debug("children arrays:  %8zu bytes (%8zu)",
                  trie->children_count * sizeof(struct trie_child_entry), trie->children_count);
        log_debug("values arrays:    %8zu bytes (%8zu)",
                  trie->values_count * sizeof(struct trie_value_entry), trie->values_count);
        log_debug("strings:          %8zu bytes",
                  trie->strings->len);
        log_debug("strings incoming: %8zu bytes (%8zu)",
                  trie->strings->in_len, trie->strings->in_count);
        log_debug("strings dedup'ed: %8zu bytes (%8zu)",
                  trie->strings->dedup_len, trie->strings->dedup_count);

        (void) mkdir_parents_label(hwdb_bin, 0755);
        err = trie_store(trie, hwdb_bin, compat);
        if (err < 0)
                return log_error_errno(err, "Failed to write database %s: %m", hwdb_bin);

        err = label_fix(hwdb_bin, 0);
        if (err < 0)
                return err;

        return r;
}

int hwdb_query(const char *modalias, const char *root) {
        _cleanup_(sd_hwdb_unrefp) sd_hwdb *hwdb = NULL;
        const char *key, *value;
        int r;

        assert(modalias);

        if (!isempty(root))
                NULSTR_FOREACH(p, hwdb_bin_paths) {
                        _cleanup_free_ char *hwdb_bin = NULL;

                        hwdb_bin = path_join(root, p);
                        if (!hwdb_bin)
                                return -ENOMEM;

                        r = sd_hwdb_new_from_path(hwdb_bin, &hwdb);
                        if (r >= 0)
                                break;
                }
        else
                r = sd_hwdb_new(&hwdb);
        if (r < 0)
                return r;

        SD_HWDB_FOREACH_PROPERTY(hwdb, modalias, key, value)
                printf("%s=%s\n", key, value);

        return 0;
}

bool hwdb_should_reload(sd_hwdb *hwdb) {
        bool found = false;
        struct stat st;

        if (!hwdb)
                return false;
        if (!hwdb->f)
                return false;

        /* if hwdb.bin doesn't exist anywhere, we need to update */
        NULSTR_FOREACH(p, hwdb_bin_paths)
                if (stat(p, &st) >= 0) {
                        found = true;
                        break;
                }
        if (!found)
                return true;

        if (timespec_load(&hwdb->st.st_mtim) != timespec_load(&st.st_mtim))
                return true;
        return false;
}

int hwdb_bypass(void) {
        int r;

        r = getenv_bool("SYSTEMD_HWDB_BYPASS");
        if (r < 0 && r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_HWDB_BYPASS, assuming no.");
        if (r <= 0)
                return false;

        log_debug("$SYSTEMD_HWDB_BYPASS is enabled, skipping execution.");
        return true;
}
