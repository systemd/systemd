/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fnmatch.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "constants.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "glob-util.h"
#include "hashmap.h"
#include "log.h"
#include "machine-tags.h"
#include "string-util.h"
#include "strv.h"

bool machine_tag_is_valid(const char *s) {
        size_t n = strlen_ptr(s);
        if (n <= 0 || n >= 256)
                return false;

        /* Don't allow "-" and "." as first char. (This is load-bearing, we want that "+"/"-" can be used as
         * prefix for adding/removing tags from the list). */
        if (strchr("-.=", s[0]))
                return false;

        /* We allow parameterization of tags, with a "=" as separator */
        const char *eq = strchr(s, '=');
        if (eq) {
                assert(eq > s);

                /* If there is an '=', then make the same restrictions as for the first char on the last char before it */
                if (strchr("-.", eq[-1]))
                        return false;
        } else {
                /* If there's no '=', then make the restriction on the very last character */
                if (strchr("-.", s[n-1]))
                        return false;
        }

        return in_charset(s, ALPHANUMERICAL "-.=");
}

static int machine_tag_key(const char *tag, char **ret) {
        assert(tag);
        assert(ret);

        /* Returns the key of a machine tag, i.e. everything up to and including the first '=', or the whole
         * tag if it has no '='. When those keys are used in a Hashmap, this allows a bare tag and an
         * assignment to coexist. */

        const char *eq = strchrnul(tag, '=');
        char *k = strndup(tag, (eq - tag) + (*eq == '='));
        if (!k)
                return -ENOMEM;

        *ret = k;
        return 0;
}

int machine_tag_list_is_valid(char **l) {
        int r;

        r = machine_tags_from_strv(l, /* graceful= */ false, /* ret= */ NULL);
        switch (r) {
        case -EINVAL:
        case -E2BIG:
                return false;
        case 0:
                return true;
        default:
                return r;
        }
}

int machine_tags_from_string(const char *s, bool graceful, char ***ret) {
        assert(ret);

        /* Parse the colon-separated TAGS= machine-info field into a sorted, deduplicated strv. */

        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        _cleanup_strv_free_ char **l = strv_split(s, ":");
        if (!l)
                return -ENOMEM;

        return machine_tags_from_strv(l, graceful, ret);
}

int machine_tags_from_strv(char **l, bool graceful, char ***ret) {
        int r;

        /* Go through a list of tags and verify each tag. Invalid tags are silently dropped if 'graceful',
         * and -EINVAL is returned otherwise. The same valueless tag may specified more than once. If the
         * same tag with listed with different values, the last value wins if 'graceful', otherwise -EINVAL
         * is returned, too. At most MACHINE_TAGS_MAX valid tags are accepted. The result is sorted only
         * after deduplication, and is NULL if no (valid) tags remain. */

        /* Maps the key of each tag to the tag itself (borrowed from 'l'). */
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        STRV_FOREACH(i, l) {
                if (!machine_tag_is_valid(*i)) {
                        if (graceful)
                                continue;

                        return -EINVAL;
                }

                _cleanup_free_ char *k = NULL;
                r = machine_tag_key(*i, &k);
                if (r < 0)
                        return r;

                r = hashmap_ensure_put(&h, &string_hash_ops_free, k, *i);
                if (r == -EEXIST) {
                        if (streq(hashmap_get(h, k), *i))
                                continue;
                        if (!graceful)
                                return -EINVAL;

                        /* when graceful, update to the later value */
                        assert_se(hashmap_update(h, k, *i) >= 0);
                } else if (r < 0)
                        return r;
                else if (r > 0) {
                        TAKE_PTR(k);  /* successfully added the new value */

                        /* bail if we are over the limit */
                        if (hashmap_size(h) > MACHINE_TAGS_MAX)
                                return -E2BIG;
                }
        }

        if (ret) {
                _cleanup_strv_free_ char **cleaned = NULL;
                size_t n = 0;
                char *v;
                HASHMAP_FOREACH(v, h) {
                        r = strv_extend_with_size(&cleaned, &n, v);
                        if (r < 0)
                                return r;
                }

                strv_sort(cleaned);
                *ret = TAKE_PTR(cleaned);
        }

        return 0;
}

/* The accumulated tag list is kept in a Hashmap that maps the key of each tag (see machine_tag_key()) to the
 * tag itself, so that adding a tag replaces any tag with the same key. Both keys and values are owned by the
 * hashmap. */

static int tags_add(Hashmap **h, const char *tag) {
        int r;

        assert(h);
        assert(tag);

        _cleanup_free_ char *k = NULL;
        r = machine_tag_key(tag, &k);
        if (r < 0)
                return r;

        _cleanup_free_ char *v = strdup(tag);
        if (!v)
                return -ENOMEM;

        /* Drop any previous tag with the same key first, as hashmap_replace() would leak the old entry. */
        _cleanup_free_ char *old_k = NULL, *old_v = NULL;
        old_v = hashmap_remove2(*h, k, (void**) &old_k);

        r = hashmap_ensure_put(h, &string_hash_ops_free_free, k, v);
        if (r < 0)
                return r;

        TAKE_PTR(k);
        TAKE_PTR(v);
        return 0;
}

static void tags_remove_matching(Hashmap *h, const char *pattern) {
        char *v, *k;

        assert(pattern);

        /* Removes all tags matching the specified glob pattern. Removing the current entry while iterating
         * is explicitly allowed by the Hashmap API. */

        HASHMAP_FOREACH_KEY(v, k, h)
                if (fnmatch(pattern, v, /* flags= */ 0) == 0) {
                        assert_se(hashmap_remove(h, k) == v);
                        free(k);
                        free(v);
                }
}

static int tags_make_hashmap(char * const *base, Hashmap **ret) {
        _cleanup_hashmap_free_ Hashmap *h = NULL;
        int r;

        STRV_FOREACH(i, base) {
                r = tags_add(&h, *i);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(h);
        return 0;
}

static int tags_hashmap_to_strv(Hashmap *h, char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        size_t n = 0;
        int r;

        if (hashmap_size(h) > MACHINE_TAGS_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                       "Too many machine tags configured (%u > %u).",
                                       hashmap_size(h), MACHINE_TAGS_MAX);

        char *v;
        HASHMAP_FOREACH(v, h) {
                r = strv_extend_with_size(&l, &n, v);
                if (r < 0)
                        return log_oom();
        }

        strv_sort(l);
        *ret = TAKE_PTR(l);
        return 0;
}

static int apply_conf_file(ConfFile *c, Hashmap **h) {
        int r;

        assert(c);
        assert(h);

        _cleanup_fclose_ FILE *f = fopen(FORMAT_PROC_FD_PATH(c->fd), "re");
        if (!f)
                return log_error_errno(errno, "Failed to open %s: %m", c->original_path);

        log_debug("Applying %s", c->original_path);

        for (unsigned line = 1;; line++) {
                _cleanup_free_ char *l = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &l);
                if (r < 0)
                        return log_error_errno(r, "Failed to read %s: %m", c->original_path);
                if (r == 0)
                        return 0;

                if (isempty(l) || strchr(COMMENTS, l[0]))
                        continue;

                for (const char *p = l;;) {
                        _cleanup_free_ char *word = NULL;

                        r = extract_first_word(&p, &word, /* separators= */ NULL, EXTRACT_RETAIN_ESCAPE);
                        if (r == -ENOMEM)
                                return log_oom();
                        if (r < 0) {
                                log_syntax(NULL, LOG_WARNING, c->original_path, line, r,
                                           "Failed to parse line, ignoring: %m");
                                break;
                        }
                        if (r == 0)
                                break;

                        const char *e = word;

                        bool remove = e[0] == '-'; /* A removal. */
                        if (remove || e[0] == '+') /* An addition. Optional '+' prefix is allowed for symmetry. */
                                e++;

                        /* Either a valid tag to add or remove, or a glob pattern to remove. */
                        if (!machine_tag_is_valid(e) && !(remove && string_is_glob(e))) {
                                log_syntax(NULL, LOG_WARNING, c->original_path, line, SYNTHETIC_ERRNO(EINVAL),
                                           "Invalid machine tag pattern '%s', ignoring.", word);
                                continue;
                        }

                        if (remove) {
                                tags_remove_matching(*h, e);
                                continue;
                        }

                        r = tags_add(h, e);
                        if (r < 0)
                                return log_oom();
                }
        }
}

int machine_tags_apply_config(const char *root, char * const *base, char ***ret) {
        int r;

        assert(ret);

        /* Reads the .tags files from the machine-tags.d/ directories below 'root' (or "/" if NULL), and
         * applies the additions and removals they declare, in the order the files are sorted in, on top of
         * the 'base' tag list. Returns the resulting list, sorted, or NULL if nothing remains. */

        ConfFile **files = NULL;
        size_t n_files = 0;
        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        _cleanup_hashmap_free_ Hashmap *h = NULL;
        r = tags_make_hashmap(base, &h);
        if (r < 0) {
                assert(r == -ENOMEM);
                return log_oom();
        }

        r = conf_files_list_strv_full(
                        ".tags",
                        root,
                        CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED | CONF_FILES_WARN,
                        (const char* const*) CONF_PATHS_STRV("machine-tags.d"),
                        &files, &n_files);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate machine-tags.d/ files: %m");

        FOREACH_ARRAY(c, files, n_files) {
                r = apply_conf_file(*c, &h);
                if (r < 0)
                        return r;
        }

        return tags_hashmap_to_strv(h, ret);
}
