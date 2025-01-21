/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "catalog.h"
#include "conf-files.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "memory-util.h"
#include "mkdir.h"
#include "path-util.h"
#include "siphash24.h"
#include "sort-util.h"
#include "sparse-endian.h"
#include "strbuf.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"

const char * const catalog_file_dirs[] = {
        "/usr/local/lib/systemd/catalog/",
        "/usr/lib/systemd/catalog/",
        NULL
};

#define CATALOG_SIGNATURE { 'R', 'H', 'H', 'H', 'K', 'S', 'L', 'P' }

typedef struct CatalogHeader {
        uint8_t signature[8];  /* "RHHHKSLP" */
        le32_t compatible_flags;
        le32_t incompatible_flags;
        le64_t header_size;
        le64_t n_items;
        le64_t catalog_item_size;
} CatalogHeader;

typedef struct CatalogItem {
        sd_id128_t id;
        char language[32]; /* One byte is used for termination, so the maximum allowed
                            * length of the string is actually 31 bytes. */
        le64_t offset;
} CatalogItem;

static void catalog_hash_func(const CatalogItem *i, struct siphash *state) {
        assert(i);
        assert(state);

        siphash24_compress_typesafe(i->id, state);
        siphash24_compress_string(i->language, state);
}

static int catalog_compare_func(const CatalogItem *a, const CatalogItem *b) {
        int r;

        assert(a);
        assert(b);

        for (size_t k = 0; k < ELEMENTSOF(b->id.bytes); k++) {
                r = CMP(a->id.bytes[k], b->id.bytes[k]);
                if (r != 0)
                        return r;
        }

        return strcmp(a->language, b->language);
}

DEFINE_PRIVATE_HASH_OPS_FULL(
                catalog_hash_ops,
                CatalogItem, catalog_hash_func, catalog_compare_func, free,
                void, free);

static bool next_header(const char **s) {
        const char *e;

        assert(s);
        assert(*s);

        e = strchr(*s, '\n');

        /* Unexpected end */
        if (!e)
                return false;

        /* End of headers */
        if (e == *s)
                return false;

        *s = e + 1;
        return true;
}

static const char* skip_header(const char *s) {
        assert(s);

        while (next_header(&s))
                ;
        return s;
}

static char* combine_entries(const char *one, const char *two) {
        const char *b1, *b2;
        size_t l1, l2, n;
        char *dest, *p;

        assert(one);
        assert(two);

        /* Find split point of headers to body */
        b1 = skip_header(one);
        b2 = skip_header(two);

        l1 = strlen(one);
        l2 = strlen(two);
        dest = new(char, l1 + l2 + 1);
        if (!dest) {
                log_oom();
                return NULL;
        }

        p = dest;

        /* Headers from @one */
        n = b1 - one;
        p = mempcpy(p, one, n);

        /* Headers from @two, these will only be found if not present above */
        n = b2 - two;
        p = mempcpy(p, two, n);

        /* Body from @one */
        n = l1 - (b1 - one);
        if (n > 0)
                p = mempcpy(p, b1, n);
        /* Body from @two */
        else {
                n = l2 - (b2 - two);
                p = mempcpy(p, b2, n);
        }

        assert(p - dest <= (ptrdiff_t)(l1 + l2));
        p[0] = '\0';
        return dest;
}

static int finish_item(
                OrderedHashmap **h,
                sd_id128_t id,
                const char *language,
                const char *payload,
                size_t payload_size) {

        _cleanup_free_ CatalogItem *i = NULL;
        _cleanup_free_ char *combined = NULL;
        char *prev;
        int r;

        assert(h);
        assert(payload);
        assert(payload_size > 0);

        i = new0(CatalogItem, 1);
        if (!i)
                return log_oom();

        i->id = id;
        if (language) {
                assert(strlen(language) > 1 && strlen(language) < 32);
                strcpy(i->language, language);
        }

        prev = ordered_hashmap_get(*h, i);
        if (prev) {
                /* Already have such an item, combine them */
                combined = combine_entries(payload, prev);
                if (!combined)
                        return log_oom();

                r = ordered_hashmap_update(*h, i, combined);
                if (r < 0)
                        return log_error_errno(r, "Failed to update catalog item: %m");

                TAKE_PTR(combined);
                free(prev);
        } else {
                /* A new item */
                combined = memdup(payload, payload_size + 1);
                if (!combined)
                        return log_oom();

                r = ordered_hashmap_ensure_put(h, &catalog_hash_ops, i, combined);
                if (r < 0)
                        return log_error_errno(r, "Failed to insert catalog item: %m");

                TAKE_PTR(i);
                TAKE_PTR(combined);
        }

        return 0;
}

int catalog_file_lang(const char *filename, char **ret) {
        char *beg, *end, *lang;

        assert(filename);
        assert(ret);

        end = endswith(filename, ".catalog");
        if (!end)
                return 0;

        beg = end - 1;
        while (beg > filename && !IN_SET(*beg, '.', '/') && end - beg < 32)
                beg--;

        if (*beg != '.' || end <= beg + 1)
                return 0;

        lang = strndup(beg + 1, end - beg - 1);
        if (!lang)
                return -ENOMEM;

        *ret = lang;
        return 1;
}

static int catalog_entry_lang(
                const char *filename,
                unsigned line,
                const char *t,
                const char *deflang,
                char **ret) {

        assert(t);

        size_t c = strlen(t);
        if (c < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "[%s:%u] Language too short.", filename, line);
        if (c > 31)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "[%s:%u] language too long.", filename, line);

        if (deflang) {
                if (streq(t, deflang)) {
                        log_warning("[%s:%u] language specified unnecessarily", filename, line);
                        return 0;
                }

                log_warning("[%s:%u] language differs from default for file", filename, line);
        }

        return strdup_to(ret, t);
}

int catalog_import_file(OrderedHashmap **h, const char *path) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *payload = NULL;
        size_t payload_size = 0;
        unsigned n = 0;
        sd_id128_t id;
        _cleanup_free_ char *deflang = NULL, *lang = NULL;
        bool got_id = false, empty_line = true;
        int r;

        assert(h);
        assert(path);

        f = fopen(path, "re");
        if (!f)
                return log_error_errno(errno, "Failed to open file %s: %m", path);

        r = catalog_file_lang(path, &deflang);
        if (r < 0)
                log_error_errno(r, "Failed to determine language for file %s: %m", path);
        if (r == 1)
                log_debug("File %s has language %s.", path, deflang);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                size_t line_len;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read file %s: %m", path);
                if (r == 0)
                        break;

                n++;

                if (isempty(line)) {
                        empty_line = true;
                        continue;
                }

                if (strchr(COMMENTS, line[0]))
                        continue;

                if (empty_line &&
                    strlen(line) >= 2+1+32 &&
                    line[0] == '-' &&
                    line[1] == '-' &&
                    line[2] == ' ' &&
                    IN_SET(line[2+1+32], ' ', '\0')) {

                        bool with_language;
                        sd_id128_t jd;

                        /* New entry */

                        with_language = line[2+1+32] != '\0';
                        line[2+1+32] = '\0';

                        if (sd_id128_from_string(line + 2 + 1, &jd) >= 0) {

                                if (got_id) {
                                        if (payload_size == 0)
                                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                                       "[%s:%u] No payload text.",
                                                                       path,
                                                                       n);

                                        r = finish_item(h, id, lang ?: deflang, payload, payload_size);
                                        if (r < 0)
                                                return r;

                                        lang = mfree(lang);
                                        payload_size = 0;
                                }

                                if (with_language) {
                                        char *t;

                                        t = strstrip(line + 2 + 1 + 32 + 1);
                                        r = catalog_entry_lang(path, n, t, deflang, &lang);
                                        if (r < 0)
                                                return r;
                                }

                                got_id = true;
                                empty_line = false;
                                id = jd;

                                continue;
                        }
                }

                /* Payload */
                if (!got_id)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] Got payload before ID.",
                                               path, n);

                line_len = strlen(line);
                if (!GREEDY_REALLOC(payload, payload_size + (empty_line ? 1 : 0) + line_len + 1 + 1))
                        return log_oom();

                if (empty_line)
                        payload[payload_size++] = '\n';
                memcpy(payload + payload_size, line, line_len);
                payload_size += line_len;
                payload[payload_size++] = '\n';
                payload[payload_size] = '\0';

                empty_line = false;
        }

        if (got_id) {
                if (payload_size == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "[%s:%u] No payload text.",
                                               path, n);

                r = finish_item(h, id, lang ?: deflang, payload, payload_size);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int64_t write_catalog(
                const char *database,
                const struct strbuf *sb,
                const CatalogItem *items,
                size_t n_items) {

        _cleanup_(unlink_and_freep) char *p = NULL;
        _cleanup_fclose_ FILE *w = NULL;
        int r;

        assert(database);
        assert(sb);
        assert(items);
        assert(n_items > 0);

        r = mkdir_parents(database, 0755);
        if (r < 0)
                return log_error_errno(r, "Failed to create parent directories of %s: %m", database);

        r = fopen_temporary(database, &w, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to open database for writing: %s: %m", database);

        CatalogHeader header = {
                .signature = CATALOG_SIGNATURE,
                .header_size = htole64(CONST_ALIGN_TO(sizeof(CatalogHeader), 8)),
                .catalog_item_size = htole64(sizeof(CatalogItem)),
                .n_items = htole64(n_items),
        };

        if (fwrite(&header, sizeof(header), 1, w) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "%s: failed to write header.", p);

        if (fwrite(items, sizeof(CatalogItem), n_items, w) != n_items)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "%s: failed to write database.", p);

        if (fwrite(sb->buf, sb->len, 1, w) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "%s: failed to write strings.", p);

        r = fflush_and_check(w);
        if (r < 0)
                return log_error_errno(r, "%s: failed to write database: %m", p);

        (void) fchmod(fileno(w), 0644);

        if (rename(p, database) < 0)
                return log_error_errno(errno, "rename (%s -> %s) failed: %m", p, database);

        p = mfree(p); /* free without unlinking */
        return ftello(w);
}

int catalog_update(const char *database, const char *root, const char* const *dirs) {
        int r;

        assert(database);

        if (!dirs)
                dirs = catalog_file_dirs;

        _cleanup_strv_free_ char **files = NULL;
        r = conf_files_list_strv(&files, ".catalog", root, 0, dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to get catalog files: %m");

        _cleanup_ordered_hashmap_free_ OrderedHashmap *h = NULL;
        STRV_FOREACH(f, files) {
                log_debug("Reading file '%s'", *f);
                r = catalog_import_file(&h, *f);
                if (r < 0)
                        return log_error_errno(r, "Failed to import file '%s': %m", *f);
        }

        if (ordered_hashmap_isempty(h)) {
                log_info("No items in catalog.");
                return 0;
        }

        log_debug("Found %u items in catalog.", ordered_hashmap_size(h));

        _cleanup_free_ CatalogItem *items = new(CatalogItem, ordered_hashmap_size(h));
        if (!items)
                return log_oom();

        _cleanup_(strbuf_freep) struct strbuf *sb = strbuf_new();
        if (!sb)
                return log_oom();

        unsigned n = 0;
        char *payload;
        CatalogItem *i;
        ORDERED_HASHMAP_FOREACH_KEY(payload, i, h) {
                log_trace("Found " SD_ID128_FORMAT_STR ", language %s",
                          SD_ID128_FORMAT_VAL(i->id),
                          isempty(i->language) ? "C" : i->language);

                ssize_t offset = strbuf_add_string(sb, payload);
                if (offset < 0)
                        return log_oom();

                i->offset = htole64((uint64_t) offset);
                items[n++] = *i;
        }

        assert(n == ordered_hashmap_size(h));
        typesafe_qsort(items, n, catalog_compare_func);

        strbuf_complete(sb);

        int64_t sz = write_catalog(database, sb, items, n);
        if (sz < 0)
                return log_error_errno(sz, "Failed to write %s: %m", database);

        log_debug("%s: wrote %u items, with %zu bytes of strings, %"PRIi64" total size.",
                  database, n, sb->len, sz);
        return 0;
}

static int open_mmap(const char *database, int *ret_fd, struct stat *ret_st, void **ret_map) {
        assert(database);
        assert(ret_fd);
        assert(ret_st);
        assert(ret_map);

        _cleanup_close_ int fd = open(database, O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        struct stat st;
        if (fstat(fd, &st) < 0)
                return -errno;

        if (st.st_size < (off_t) sizeof(CatalogHeader) || file_offset_beyond_memory_size(st.st_size))
                return -EINVAL;

        void *p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
                return -errno;

        const CatalogHeader *h = p;
        if (memcmp(h->signature, (const uint8_t[]) CATALOG_SIGNATURE, sizeof(h->signature)) != 0 ||
            le64toh(h->header_size) < sizeof(CatalogHeader) ||
            le64toh(h->catalog_item_size) < sizeof(CatalogItem) ||
            h->incompatible_flags != 0 ||
            le64toh(h->n_items) <= 0 ||
            st.st_size < (off_t) (le64toh(h->header_size) + le64toh(h->catalog_item_size) * le64toh(h->n_items))) {
                munmap(p, st.st_size);
                return -EBADMSG;
        }

        *ret_fd = TAKE_FD(fd);
        *ret_st = st;
        *ret_map = p;
        return 0;
}

static const char* find_id(const void *p, sd_id128_t id) {
        CatalogItem *f = NULL, key = { .id = id };
        const CatalogHeader *h = ASSERT_PTR(p);
        const char *loc;

        loc = setlocale(LC_MESSAGES, NULL);
        if (!isempty(loc) && !STR_IN_SET(loc, "C", "POSIX")) {
                size_t len;

                len = strcspn(loc, ".@");
                if (len > sizeof(key.language) - 1)
                        log_debug("LC_MESSAGES value too long, ignoring: \"%.*s\"", (int) len, loc);
                else {
                        strncpy(key.language, loc, len);
                        key.language[len] = '\0';

                        f = bsearch(&key,
                                    (const uint8_t*) p + le64toh(h->header_size),
                                    le64toh(h->n_items),
                                    le64toh(h->catalog_item_size),
                                    (comparison_fn_t) catalog_compare_func);
                        if (!f) {
                                char *e;

                                e = strchr(key.language, '_');
                                if (e) {
                                        *e = 0;
                                        f = bsearch(&key,
                                                    (const uint8_t*) p + le64toh(h->header_size),
                                                    le64toh(h->n_items),
                                                    le64toh(h->catalog_item_size),
                                                    (comparison_fn_t) catalog_compare_func);
                                }
                        }
                }
        }

        if (!f) {
                zero(key.language);
                f = bsearch(&key,
                            (const uint8_t*) p + le64toh(h->header_size),
                            le64toh(h->n_items),
                            le64toh(h->catalog_item_size),
                            (comparison_fn_t) catalog_compare_func);
        }

        if (!f)
                return NULL;

        return (const char*) p +
                le64toh(h->header_size) +
                le64toh(h->n_items) * le64toh(h->catalog_item_size) +
                le64toh(f->offset);
}

int catalog_get(const char *database, sd_id128_t id, char **ret_text) {
        int r;

        assert(database);
        assert(ret_text);

        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        void *p;
        r = open_mmap(database, &fd, &st, &p);
        if (r < 0)
                return r;

        const char *s = find_id(p, id);
        if (!s)
                r = -ENOENT;
        else
                r = strdup_to(ret_text, s);

        (void) munmap(p, st.st_size);
        return r;
}

static char* find_header(const char *s, const char *header) {

        assert(s);
        assert(header);

        for (;;) {
                const char *v;

                v = startswith(s, header);
                if (v) {
                        v += strspn(v, WHITESPACE);
                        return strndup(v, strcspn(v, NEWLINE));
                }

                if (!next_header(&s))
                        return NULL;
        }
}

static void dump_catalog_entry(FILE *f, sd_id128_t id, const char *s, bool oneline) {
        assert(s);

        if (!f)
                f = stdout;

        if (oneline) {
                _cleanup_free_ char *subject = NULL, *defined_by = NULL;

                subject = find_header(s, "Subject:");
                defined_by = find_header(s, "Defined-By:");

                fprintf(f, SD_ID128_FORMAT_STR " %s: %s\n",
                        SD_ID128_FORMAT_VAL(id),
                        strna(defined_by), strna(subject));
        } else
                fprintf(f, "-- " SD_ID128_FORMAT_STR "\n%s\n",
                        SD_ID128_FORMAT_VAL(id), s);
}

int catalog_list(FILE *f, const char *database, bool oneline) {
        int r;

        assert(database);

        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        void *p;
        r = open_mmap(database, &fd, &st, &p);
        if (r < 0)
                return r;

        const CatalogHeader *h = p;
        const CatalogItem *items = (const CatalogItem*) ((const uint8_t*) p + le64toh(h->header_size));

        sd_id128_t last_id;
        bool last_id_set = false;
        for (size_t n = 0; n < le64toh(h->n_items); n++) {
                const char *s;

                if (last_id_set && sd_id128_equal(last_id, items[n].id))
                        continue;

                assert_se(s = find_id(p, items[n].id));

                dump_catalog_entry(f, items[n].id, s, oneline);

                last_id_set = true;
                last_id = items[n].id;
        }

        (void) munmap(p, st.st_size);
        return 0;
}

int catalog_list_items(FILE *f, const char *database, bool oneline, char **items) {
        int r, ret = 0;

        assert(database);

        STRV_FOREACH(item, items) {
                sd_id128_t id;
                r = sd_id128_from_string(*item, &id);
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to parse id128 '%s': %m", *item));
                        continue;
                }

                _cleanup_free_ char *msg = NULL;
                r = catalog_get(database, id, &msg);
                if (r < 0) {
                        RET_GATHER(ret, log_full_errno(r == -ENOENT ? LOG_NOTICE : LOG_ERR, r,
                                                       "Failed to retrieve catalog entry for '%s': %m", *item));
                        continue;
                }

                dump_catalog_entry(f, id, msg, oneline);
        }

        return ret;
}
