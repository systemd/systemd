/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/ipv6.h>
#include <stdio.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "calendarspec.h"
#include "chase.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "dns-domain.h"
#include "escape.h"
#include "ether-addr-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hash-funcs.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "in-addr-prefix-util.h"
#include "ip-protocol-list.h"
#include "log.h"
#include "missing_network.h"
#include "nulstr-util.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "percent-util.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "set.h"
#include "signal-util.h"
#include "siphash24.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "syslog-util.h"
#include "time-util.h"
#include "utf8.h"

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(config_file_hash_ops_fclose,
                                              char, path_hash_func, path_compare,
                                              FILE, safe_fclose);

int config_item_table_lookup(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *ret_func,
                int *ret_ltype,
                void **ret_data,
                void *userdata) {

        assert(table);
        assert(lvalue);
        assert(ret_func);
        assert(ret_ltype);
        assert(ret_data);

        for (const ConfigTableItem *t = table; t->lvalue; t++) {

                if (!streq(lvalue, t->lvalue))
                        continue;

                if (!streq_ptr(section, t->section))
                        continue;

                *ret_func = t->parse;
                *ret_ltype = t->ltype;
                *ret_data = t->data;
                return 1;
        }

        *ret_func = NULL;
        *ret_ltype = 0;
        *ret_data = NULL;
        return 0;
}

int config_item_perf_lookup(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *ret_func,
                int *ret_ltype,
                void **ret_data,
                void *userdata) {

        ConfigPerfItemLookup lookup = (ConfigPerfItemLookup) table;
        const ConfigPerfItem *p;

        assert(table);
        assert(lvalue);
        assert(ret_func);
        assert(ret_ltype);
        assert(ret_data);

        if (section) {
                const char *key;

                key = strjoina(section, ".", lvalue);
                p = lookup(key, strlen(key));
        } else
                p = lookup(lvalue, strlen(lvalue));
        if (!p) {
                *ret_func = NULL;
                *ret_ltype = 0;
                *ret_data = NULL;
                return 0;
        }

        *ret_func = p->parse;
        *ret_ltype = p->ltype;
        *ret_data = (uint8_t*) userdata + p->offset;
        return 1;
}

/* Run the user supplied parser for an assignment */
static int next_assignment(
                const char *unit,
                const char *filename,
                unsigned line,
                ConfigItemLookup lookup,
                const void *table,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                ConfigParseFlags flags,
                void *userdata) {

        ConfigParserCallback func = NULL;
        int ltype = 0;
        void *data = NULL;
        int r;

        assert(filename);
        assert(line > 0);
        assert(lookup);
        assert(lvalue);
        assert(rvalue);

        r = lookup(table, section, lvalue, &func, &ltype, &data, userdata);
        if (r < 0)
                return r;
        if (r > 0) {
                if (!func)
                        return 0;

                return func(unit, filename, line, section, section_line,
                            lvalue, ltype, rvalue, data, userdata);
        }

        /* Warn about unknown non-extension fields. */
        if (!(flags & CONFIG_PARSE_RELAXED) && !startswith(lvalue, "X-"))
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Unknown key '%s'%s%s%s, ignoring.",
                           lvalue,
                           section ? " in section [" : "",
                           strempty(section),
                           section ? "]" : "");

        return 0;
}

/* Parse a single logical line */
static int parse_line(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                char **section,
                unsigned *section_line,
                bool *section_ignored,
                char *l, /* is modified */
                void *userdata) {

        char *e;

        assert(filename);
        assert(line > 0);
        assert(lookup);
        assert(l);

        l = strstrip(l);
        if (isempty(l))
                return 0;

        if (l[0] == '\n')
                return 0;

        if (!utf8_is_valid(l))
                return log_syntax_invalid_utf8(unit, LOG_WARNING, filename, line, l);

        if (l[0] == '[') {
                _cleanup_free_ char *n = NULL;
                size_t k;

                k = strlen(l);
                assert(k > 0);

                if (l[k-1] != ']')
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EBADMSG), "Invalid section header '%s'", l);

                n = strndup(l+1, k-2);
                if (!n)
                        return log_oom();

                if (!string_is_safe(n))
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EBADMSG), "Bad characters in section header '%s'", l);

                if (sections && !nulstr_contains(sections, n)) {
                        bool ignore;

                        ignore = (flags & CONFIG_PARSE_RELAXED) || startswith(n, "X-");

                        if (!ignore)
                                NULSTR_FOREACH(t, sections)
                                        if (streq_ptr(n, startswith(t, "-"))) { /* Ignore sections prefixed with "-" in valid section list */
                                                ignore = true;
                                                break;
                                        }

                        if (!ignore)
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Unknown section '%s'. Ignoring.", n);

                        *section = mfree(*section);
                        *section_line = 0;
                        *section_ignored = true;
                } else {
                        free_and_replace(*section, n);
                        *section_line = line;
                        *section_ignored = false;
                }

                return 0;
        }

        if (sections && !*section) {
                if (!(flags & CONFIG_PARSE_RELAXED) && !*section_ignored)
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Assignment outside of section. Ignoring.");

                return 0;
        }

        e = strchr(l, '=');
        if (!e)
                return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                  "Missing '=', ignoring line.");
        if (e == l)
                return log_syntax(unit, LOG_WARNING, filename, line, 0,
                                  "Missing key name before '=', ignoring line.");

        *e = 0;
        e++;

        return next_assignment(unit,
                               filename,
                               line,
                               lookup,
                               table,
                               *section,
                               *section_line,
                               strstrip(l),
                               strstrip(e),
                               flags,
                               userdata);
}

/* Go through the file and parse each line */
int config_parse(
                const char *unit,
                const char *filename,
                FILE *f,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                struct stat *ret_stat) {

        _cleanup_free_ char *section = NULL, *continuation = NULL;
        _cleanup_fclose_ FILE *ours = NULL;
        unsigned line = 0, section_line = 0;
        bool section_ignored = false, bom_seen = false;
        struct stat st;
        int r, fd;

        assert(filename);
        assert(lookup);

        if (!f) {
                f = ours = fopen(filename, "re");
                if (!f) {
                        /* Only log on request, except for ENOENT,
                         * since we return 0 to the caller. */
                        if ((flags & CONFIG_PARSE_WARN) || errno == ENOENT)
                                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_ERR, errno,
                                               "Failed to open configuration file '%s': %m", filename);

                        if (errno == ENOENT) {
                                if (ret_stat)
                                        *ret_stat = (struct stat) {};

                                return 0;
                        }

                        return -errno;
                }
        }

        fd = fileno(f);
        if (fd >= 0) { /* stream might not have an fd, let's be careful hence */

                if (fstat(fd, &st) < 0)
                        return log_full_errno(FLAGS_SET(flags, CONFIG_PARSE_WARN) ? LOG_ERR : LOG_DEBUG, errno,
                                              "Failed to fstat(%s): %m", filename);

                (void) stat_warn_permissions(filename, &st);
        } else
                st = (struct stat) {};

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                bool escaped = false;
                char *l, *p, *e;

                r = read_line(f, LONG_LINE_MAX, &buf);
                if (r == 0)
                        break;
                if (r == -ENOBUFS) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_error_errno(r, "%s:%u: Line too long", filename, line);

                        return r;
                }
                if (r < 0) {
                        if (FLAGS_SET(flags, CONFIG_PARSE_WARN))
                                log_error_errno(r, "%s:%u: Error while reading configuration file: %m", filename, line);

                        return r;
                }

                line++;

                l = skip_leading_chars(buf, WHITESPACE);
                if (*l != '\0' && strchr(COMMENTS, *l))
                        continue;

                l = buf;
                if (!bom_seen) {
                        char *q;

                        q = startswith(buf, UTF8_BYTE_ORDER_MARK);
                        if (q) {
                                l = q;
                                bom_seen = true;
                        }
                }

                if (continuation) {
                        if (strlen(continuation) + strlen(l) > LONG_LINE_MAX) {
                                if (flags & CONFIG_PARSE_WARN)
                                        log_error("%s:%u: Continuation line too long", filename, line);
                                return -ENOBUFS;
                        }

                        if (!strextend(&continuation, l)) {
                                if (flags & CONFIG_PARSE_WARN)
                                        log_oom();
                                return -ENOMEM;
                        }

                        p = continuation;
                } else
                        p = l;

                for (e = p; *e; e++) {
                        if (escaped)
                                escaped = false;
                        else if (*e == '\\')
                                escaped = true;
                }

                if (escaped) {
                        *(e-1) = ' ';

                        if (!continuation) {
                                continuation = strdup(l);
                                if (!continuation) {
                                        if (flags & CONFIG_PARSE_WARN)
                                                log_oom();
                                        return -ENOMEM;
                                }
                        }

                        continue;
                }

                r = parse_line(unit,
                               filename,
                               line,
                               sections,
                               lookup,
                               table,
                               flags,
                               &section,
                               &section_line,
                               &section_ignored,
                               p,
                               userdata);
                if (r < 0) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_warning_errno(r, "%s:%u: Failed to parse file: %m", filename, line);
                        return r;
                }

                continuation = mfree(continuation);
        }

        if (continuation) {
                r = parse_line(unit,
                               filename,
                               ++line,
                               sections,
                               lookup,
                               table,
                               flags,
                               &section,
                               &section_line,
                               &section_ignored,
                               continuation,
                               userdata);
                if (r < 0) {
                        if (flags & CONFIG_PARSE_WARN)
                                log_warning_errno(r, "%s:%u: Failed to parse file: %m", filename, line);
                        return r;
                }
        }

        if (ret_stat)
                *ret_stat = st;

        return 1;
}

int hashmap_put_stats_by_path(Hashmap **stats_by_path, const char *path, const struct stat *st) {
        _cleanup_free_ struct stat *st_copy = NULL;
        _cleanup_free_ char *path_copy = NULL;
        int r;

        assert(stats_by_path);
        assert(path);
        assert(st);

        st_copy = newdup(struct stat, st, 1);
        if (!st_copy)
                return -ENOMEM;

        path_copy = strdup(path);
        if (!path_copy)
                return -ENOMEM;

        r = hashmap_ensure_put(stats_by_path, &path_hash_ops_free_free, path_copy, st_copy);
        if (r < 0)
                return r;

        assert(r > 0);
        TAKE_PTR(path_copy);
        TAKE_PTR(st_copy);
        return 0;
}

static int config_parse_many_files(
                const char *root,
                const char* const* conf_files,
                char **files,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path) {

        _cleanup_hashmap_free_ Hashmap *stats_by_path = NULL;
        _cleanup_ordered_hashmap_free_ OrderedHashmap *dropins = NULL;
        _cleanup_set_free_ Set *inodes = NULL;
        struct stat st;
        int r, level = FLAGS_SET(flags, CONFIG_PARSE_WARN) ? LOG_WARNING : LOG_DEBUG;

        if (ret_stats_by_path) {
                stats_by_path = hashmap_new(&path_hash_ops_free_free);
                if (!stats_by_path)
                        return log_oom_full(level);
        }

        STRV_FOREACH(fn, files) {
                _cleanup_fclose_ FILE *f = NULL;
                _cleanup_free_ char *fname = NULL;

                r = chase_and_fopen_unlocked(*fn, root, CHASE_AT_RESOLVE_IN_ROOT, "re", &fname, &f);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_full_errno(level, r, "Failed to open %s: %m", *fn);

                int fd = fileno(f);

                r = ordered_hashmap_ensure_put(&dropins, &config_file_hash_ops_fclose, *fn, f);
                if (r < 0) {
                        assert(r == -ENOMEM);
                        return log_oom_full(level);
                }
                assert(r > 0);
                TAKE_PTR(f);

                /* Get inodes for all drop-ins. Later we'll verify if main config is a symlink to or is
                 * symlinked as one of them. If so, we skip reading main config file directly. */

                _cleanup_free_ struct stat *st_dropin = new(struct stat, 1);
                if (!st_dropin)
                        return log_oom_full(level);

                if (fstat(fd, st_dropin) < 0)
                        return log_full_errno(level, errno, "Failed to stat %s: %m", *fn);

                r = set_ensure_consume(&inodes, &inode_hash_ops, TAKE_PTR(st_dropin));
                if (r < 0)
                        return log_oom_full(level);
        }

        /* First read the first found main config file. */
        STRV_FOREACH(fn, conf_files) {
                _cleanup_fclose_ FILE *f = NULL;

                r = chase_and_fopen_unlocked(*fn, root, CHASE_AT_RESOLVE_IN_ROOT, "re", NULL, &f);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_full_errno(level, r, "Failed to open %s: %m", *fn);

                if (inodes) {
                        if (fstat(fileno(f), &st) < 0)
                                return log_full_errno(level, errno, "Failed to stat %s: %m", *fn);

                        if (set_contains(inodes, &st)) {
                                log_debug("%s: symlink to/symlinked as drop-in, will be read later.", *fn);
                                break;
                        }
                }

                r = config_parse(/* unit= */ NULL, *fn, f, sections, lookup, table, flags, userdata, &st);
                if (r < 0)
                        return r; /* config_parse() logs internally. */
                assert(r > 0);

                if (ret_stats_by_path) {
                        r = hashmap_put_stats_by_path(&stats_by_path, *fn, &st);
                        if (r < 0)
                                return log_full_errno(level, r, "Failed to save stats of %s: %m", *fn);
                }

                break;
        }

        /* Then read all the drop-ins. */

        const char *path_dropin;
        FILE *f_dropin;
        ORDERED_HASHMAP_FOREACH_KEY(f_dropin, path_dropin, dropins) {
                r = config_parse(/* unit= */ NULL, path_dropin, f_dropin, sections, lookup, table, flags, userdata, &st);
                if (r < 0)
                        return r; /* config_parse() logs internally. */
                assert(r > 0);

                if (ret_stats_by_path) {
                        r = hashmap_put_stats_by_path(&stats_by_path, path_dropin, &st);
                        if (r < 0)
                                return log_full_errno(level, r, "Failed to save stats of %s: %m", path_dropin);
                }
        }

        if (ret_stats_by_path)
                *ret_stats_by_path = TAKE_PTR(stats_by_path);

        return 0;
}

/* Parse each config file in the directories specified as strv. */
int config_parse_many(
                const char* const* conf_files,
                const char* const* conf_file_dirs,
                const char *dropin_dirname,
                const char *root,
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path,
                char ***ret_dropin_files) {

        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(conf_file_dirs);
        assert(dropin_dirname);
        assert(table);

        r = conf_files_list_dropins(&files, dropin_dirname, root, conf_file_dirs);
        if (r < 0)
                return log_full_errno(FLAGS_SET(flags, CONFIG_PARSE_WARN) ? LOG_WARNING : LOG_DEBUG, r,
                                      "Failed to list up drop-in configs in %s: %m", dropin_dirname);

        r = config_parse_many_files(root, conf_files, files, sections, lookup, table, flags, userdata, ret_stats_by_path);
        if (r < 0)
                return r; /* config_parse_many_files() logs internally. */

        if (ret_dropin_files)
                *ret_dropin_files = TAKE_PTR(files);

        return 0;
}

int config_parse_standard_file_with_dropins_full(
                const char *root,
                const char *main_file,    /* A path like "systemd/frobnicator.conf" */
                const char *sections,
                ConfigItemLookup lookup,
                const void *table,
                ConfigParseFlags flags,
                void *userdata,
                Hashmap **ret_stats_by_path,
                char ***ret_dropin_files) {

        const char* const *conf_paths = (const char* const*) CONF_PATHS_STRV("");
        _cleanup_strv_free_ char **configs = NULL;
        int r, level = FLAGS_SET(flags, CONFIG_PARSE_WARN) ? LOG_WARNING : LOG_DEBUG;

        /* Build the list of main config files */
        r = strv_extend_strv_biconcat(&configs, root, conf_paths, main_file);
        if (r < 0)
                return log_oom_full(level);

        _cleanup_free_ char *dropin_dirname = strjoin(main_file, ".d");
        if (!dropin_dirname)
                return log_oom_full(level);

        return config_parse_many(
                        (const char* const*) configs,
                        conf_paths,
                        dropin_dirname,
                        root,
                        sections,
                        lookup,
                        table,
                        flags,
                        userdata,
                        ret_stats_by_path,
                        ret_dropin_files);
}

static int dropins_get_stats_by_path(
                const char* conf_file,
                const char* const* conf_file_dirs,
                Hashmap **stats_by_path) {

        _cleanup_strv_free_ char **files = NULL;
        _cleanup_free_ char *dropin_dirname = NULL;
        int r;

        assert(conf_file);
        assert(conf_file_dirs);
        assert(stats_by_path);

        r = path_extract_filename(conf_file, &dropin_dirname);
        if (r < 0)
                return r;
        if (r == O_DIRECTORY)
                return -EINVAL;

        if (!strextend(&dropin_dirname, ".d"))
                return -ENOMEM;

        r = conf_files_list_dropins(&files, dropin_dirname, /* root = */ NULL, conf_file_dirs);
        if (r < 0)
                return r;

        STRV_FOREACH(fn, files) {
                struct stat st;

                if (stat(*fn, &st) < 0) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                r = hashmap_put_stats_by_path(stats_by_path, *fn, &st);
                if (r < 0)
                        return r;
        }

        return 0;
}

int config_get_stats_by_path(
                const char *suffix,
                const char *root,
                unsigned flags,
                const char* const* dirs,
                bool check_dropins,
                Hashmap **ret) {

        _cleanup_hashmap_free_ Hashmap *stats_by_path = NULL;
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(suffix);
        assert(dirs);
        assert(ret);

        /* Unlike config_parse(), this does not support stream. */

        r = conf_files_list_strv(&files, suffix, root, flags, dirs);
        if (r < 0)
                return r;

        STRV_FOREACH(f, files) {
                struct stat st;

                /* First read the main config file. */
                if (stat(*f, &st) < 0) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                /* Skipping an empty file. */
                if (null_or_empty(&st))
                        continue;

                r = hashmap_put_stats_by_path(&stats_by_path, *f, &st);
                if (r < 0)
                        return r;

                if (!check_dropins)
                        continue;

                /* Then read all the drop-ins if requested. */
                r = dropins_get_stats_by_path(*f, dirs, &stats_by_path);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(stats_by_path);
        return 0;
}

bool stats_by_path_equal(Hashmap *a, Hashmap *b) {
        struct stat *st_a, *st_b;
        const char *path;

        if (hashmap_size(a) != hashmap_size(b))
                return false;

        HASHMAP_FOREACH_KEY(st_a, path, a) {
                st_b = hashmap_get(b, path);
                if (!st_b)
                        return false;

                if (!stat_inode_unmodified(st_a, st_b))
                        return false;
        }

        return true;
}

int config_section_parse(
                const ConfigSectionParser *parsers,
                size_t n_parsers,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *userdata) {

        assert(parsers);
        assert(n_parsers > 0);
        assert(ltype >= 0);
        assert((size_t) ltype < n_parsers);
        assert(userdata);

        const ConfigSectionParser *e = parsers + ltype;
        assert(e->parser);

        /* This is used when a object is dynamically allocated per [SECTION] in a config parser, e.g.
         * [Address] for systemd.network. Takes the allocated object as 'userdata', then it is passed to
         * config parsers in the table. The 'data' field points to an element of the passed object, where
         * its offset is given by the table. */

        return e->parser(unit, filename, line, section, section_line, lvalue, e->ltype, rvalue,
                         (uint8_t*) userdata + e->offset, userdata);
}

void config_section_hash_func(const ConfigSection *c, struct siphash *state) {
        siphash24_compress_string(c->filename, state);
        siphash24_compress_typesafe(c->line, state);
}

int config_section_compare_func(const ConfigSection *x, const ConfigSection *y) {
        int r;

        r = strcmp(x->filename, y->filename);
        if (r != 0)
                return r;

        return CMP(x->line, y->line);
}

DEFINE_HASH_OPS(config_section_hash_ops, ConfigSection, config_section_hash_func, config_section_compare_func);

int config_section_new(const char *filename, unsigned line, ConfigSection **ret) {
        ConfigSection *cs;

        assert(filename);
        assert(line > 0);
        assert(ret);

        cs = malloc0(offsetof(ConfigSection, filename) + strlen(filename) + 1);
        if (!cs)
                return -ENOMEM;

        strcpy(cs->filename, filename);
        cs->line = line;

        *ret = TAKE_PTR(cs);
        return 0;
}

static int _hashmap_by_section_find_unused_line(
                HashmapBase *entries_by_section,
                const char *filename,
                unsigned *ret) {

        ConfigSection *cs;
        unsigned n = 0;
        void *entry;

        HASHMAP_BASE_FOREACH_KEY(entry, cs, entries_by_section) {
                if (filename && !streq(cs->filename, filename))
                        continue;
                n = MAX(n, cs->line);
        }

        /* overflow? */
        if (n >= UINT_MAX)
                return -EFBIG;

        *ret = n + 1;
        return 0;
}

int hashmap_by_section_find_unused_line(
        Hashmap *entries_by_section,
        const char *filename,
        unsigned *ret) {

        return _hashmap_by_section_find_unused_line(HASHMAP_BASE(entries_by_section), filename, ret);
}

int ordered_hashmap_by_section_find_unused_line(
        OrderedHashmap *entries_by_section,
        const char *filename,
        unsigned *ret) {

        return _hashmap_by_section_find_unused_line(HASHMAP_BASE(entries_by_section), filename, ret);
}

#define DEFINE_PARSER(type, vartype, conv_func)                         \
        DEFINE_CONFIG_PARSE_PTR(config_parse_##type, conv_func, vartype)

DEFINE_PARSER(int, int, safe_atoi);
DEFINE_PARSER(long, long, safe_atoli);
DEFINE_PARSER(uint8, uint8_t, safe_atou8);
DEFINE_PARSER(uint16, uint16_t, safe_atou16);
DEFINE_PARSER(uint32, uint32_t, safe_atou32);
DEFINE_PARSER(int32, int32_t, safe_atoi32);
DEFINE_PARSER(uint64, uint64_t, safe_atou64);
DEFINE_PARSER(unsigned, unsigned, safe_atou);
DEFINE_PARSER(double, double, safe_atod);
DEFINE_PARSER(nsec, nsec_t, parse_nsec);
DEFINE_PARSER(sec, usec_t, parse_sec);
DEFINE_PARSER(sec_def_infinity, usec_t, parse_sec_def_infinity);
DEFINE_PARSER(mode, mode_t, parse_mode);
DEFINE_PARSER(pid, pid_t, parse_pid);

int config_parse_iec_size(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        size_t *sz = ASSERT_PTR(data);
        uint64_t v;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_size(rvalue, 1024, &v);
        if (r >= 0 && (uint64_t) (size_t) v != v)
                r = -ERANGE;
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        *sz = (size_t) v;
        return 1;
}

int config_parse_si_uint64(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *sz = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_size(rvalue, 1000, sz);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1;
}

int config_parse_iec_uint64(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *bytes = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_size(rvalue, 1024, bytes);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1;
}

int config_parse_iec_uint64_infinity(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *bytes = ASSERT_PTR(data);

        assert(rvalue);

        if (streq(rvalue, "infinity")) {
                *bytes = UINT64_MAX;
                return 1;
        }

        return config_parse_iec_uint64(unit, filename, line, section, section_line, lvalue, ltype, rvalue, data, userdata);
}

int config_parse_bool(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        bool *b = ASSERT_PTR(data);
        bool fatal = ltype;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_boolean(rvalue);
        if (r < 0) {
                log_syntax_parse_error_full(unit, filename, line, r, fatal, lvalue, rvalue);
                return fatal ? -ENOEXEC : 0;
        }

        *b = r;
        return 1; /* set */
}

int config_parse_uint32_flag(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t *flags = ASSERT_PTR(data);
        int r;

        assert(ltype != 0);

        r = isempty(rvalue) ? 0 : parse_boolean(rvalue);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        SET_FLAG(*flags, ltype, r);
        return 1;
}

int config_parse_uint32_invert_flag(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t *flags = ASSERT_PTR(data);
        int r;

        assert(ltype != 0);

        r = isempty(rvalue) ? 0 : parse_boolean(rvalue);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        SET_FLAG(*flags, ltype, !r);
        return 1;
}

int config_parse_id128(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        sd_id128_t *result = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = id128_from_string_nonzero(rvalue, result);
        if (r == -ENXIO) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "128-bit ID/UUID is all 0, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1;
}

int config_parse_tristate(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int r, *t = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        /* A tristate is pretty much a boolean, except that it can also take an empty string,
         * indicating "uninitialized", much like NULL is for a pointer type. */

        if (isempty(rvalue)) {
                *t = -1;
                return 1;
        }

        r = parse_tristate(rvalue, t);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1;
}

int config_parse_string(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *s = mfree(*s);
                return 1;
        }

        if (FLAGS_SET(ltype, CONFIG_PARSE_STRING_SAFE) && !string_is_safe(rvalue)) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(rvalue);
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified string contains unsafe characters, ignoring: %s", strna(escaped));
                return 0;
        }

        if (FLAGS_SET(ltype, CONFIG_PARSE_STRING_ASCII) && !ascii_is_valid(rvalue)) {
                _cleanup_free_ char *escaped = NULL;

                escaped = cescape(rvalue);
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified string contains invalid ASCII characters, ignoring: %s", strna(escaped));
                return 0;
        }

        r = free_and_strdup_warn(s, rvalue);
        if (r < 0)
                return r;

        return 1;
}

int config_parse_dns_name(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **hostname = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *hostname = mfree(*hostname);
                return 1;
        }

        r = dns_name_is_valid(rvalue);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to check validity of DNS domain name '%s', ignoring assignment: %m", rvalue);
                return 0;
        }
        if (r == 0) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified invalid DNS domain name, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = free_and_strdup_warn(hostname, rvalue);
        if (r < 0)
                return r;

        return 1;
}

int config_parse_hostname(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **hostname = ASSERT_PTR(data);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *hostname = mfree(*hostname);
                return 1;
        }

        if (!hostname_is_valid(rvalue, 0)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Specified invalid hostname, ignoring assignment: %s", rvalue);
                return 0;
        }

        return config_parse_dns_name(unit, filename, line, section, section_line,
                                     lvalue, ltype, rvalue, data, userdata);
}

int config_parse_path(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *n = NULL;
        bool fatal = ltype;
        char **s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *s = mfree(*s);
                return 1;
        }

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        r = path_simplify_and_warn(n, PATH_CHECK_ABSOLUTE | (fatal ? PATH_CHECK_FATAL : 0), unit, filename, line, lvalue);
        if (r < 0)
                return fatal ? -ENOEXEC : 0;

        free_and_replace(*s, n);
        return 1;
}

int config_parse_strv(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype, /* When true, duplicated entries will be filtered. */
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***sv = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *sv = strv_free(*sv);
                return 1;
        }

        _cleanup_strv_free_ char **strv = NULL;
        for (const char *p = rvalue;;) {
                char *word;

                r = extract_first_word(&p, &word, NULL, EXTRACT_UNQUOTE|EXTRACT_RETAIN_ESCAPE);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        break;

                r = strv_consume(&strv, word);
                if (r < 0)
                        return log_oom();
        }

        r = strv_extend_strv_consume(sv, TAKE_PTR(strv), /* filter_duplicates = */ ltype);
        if (r < 0)
                return log_oom();

        return 1;
}

int config_parse_warn_compat(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Disabled reason = ltype;

        switch (reason) {

        case DISABLED_CONFIGURATION:
                log_syntax(unit, LOG_DEBUG, filename, line, 0,
                           "Support for option %s= has been disabled at compile time and it is ignored", lvalue);
                break;

        case DISABLED_LEGACY:
                log_syntax(unit, LOG_INFO, filename, line, 0,
                           "Support for option %s= has been removed and it is ignored", lvalue);
                break;

        case DISABLED_EXPERIMENTAL:
                log_syntax(unit, LOG_INFO, filename, line, 0,
                           "Support for option %s= has not yet been enabled and it is ignored", lvalue);
                break;
        }

        return 0;
}

int config_parse_log_facility(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = log_facility_unshifted_from_string(rvalue);
        if (x < 0)
                return log_syntax_parse_error(unit, filename, line, x, lvalue, rvalue);

        *o = (x << 3) | LOG_PRI(*o);

        return 1;
}

int config_parse_log_level(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = log_level_from_string(rvalue);
        if (x < 0)
                return log_syntax_parse_error(unit, filename, line, x, lvalue, rvalue);

        if (*o < 0) /* if it wasn't initialized so far, assume zero facility */
                *o = x;
        else
                *o = (*o & LOG_FACMASK) | x;

        return 1;
}

int config_parse_signal(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *sig = data, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(sig);

        r = signal_from_string(rvalue);
        if (r <= 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        *sig = r;
        return 1;
}

int config_parse_personality(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        unsigned long *personality = data, p;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(personality);

        if (isempty(rvalue)) {
                *personality = PERSONALITY_INVALID;
                return 1;
        }

        p = personality_from_string(rvalue);
        if (p == PERSONALITY_INVALID)
                return log_syntax_parse_error(unit, filename, line, 0, lvalue, rvalue);

        *personality = p;
        return 1;
}

int config_parse_ifname(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *s = mfree(*s);
                return 1;
        }

        if (!ifname_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Interface name is not valid or too long, ignoring assignment: %s", rvalue);
                return 0;
        }

        r = free_and_strdup_warn(s, rvalue);
        if (r < 0)
                return r;

        return 1;
}

int config_parse_ifnames(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_strv_free_ char **names = NULL;
        char ***s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *s = strv_free(*s);
                return 1;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        break;

                if (!ifname_valid_full(word, ltype)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0,
                                   "Interface name is not valid or too long, ignoring assignment: %s",
                                   word);
                        continue;
                }

                r = strv_consume(&names, TAKE_PTR(word));
                if (r < 0)
                        return log_oom();
        }

        r = strv_extend_strv(s, names, true);
        if (r < 0)
                return log_oom();

        return 1;
}

int config_parse_ip_port(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint16_t *s = ASSERT_PTR(data);
        uint16_t port;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *s = 0;
                return 1;
        }

        r = parse_ip_port(rvalue, &port);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        *s = port;
        return 1;
}

int config_parse_mtu(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint32_t *mtu = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = parse_mtu(ltype, rvalue, mtu);
        if (r == -ERANGE) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Maximum transfer unit (MTU) value out of range. Permitted range is %" PRIu32 "…%" PRIu32 ", ignoring: %s",
                           (uint32_t) (ltype == AF_INET6 ? IPV6_MIN_MTU : IPV4_MIN_MTU), (uint32_t) UINT32_MAX,
                           rvalue);
                return 0;
        }
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1;
}

int config_parse_rlimit(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        struct rlimit **rl = data, d = {};
        int r;

        assert(rvalue);
        assert(rl);

        r = rlimit_parse(ltype, rvalue, &d);
        if (r == -EILSEQ) {
                log_syntax(unit, LOG_WARNING, filename, line, r, "Soft resource limit chosen higher than hard limit, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        if (rl[ltype])
                *rl[ltype] = d;
        else {
                rl[ltype] = newdup(struct rlimit, &d, 1);
                if (!rl[ltype])
                        return log_oom();
        }

        return 1;
}

int config_parse_permille(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        unsigned *permille = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_permille(rvalue);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        *permille = (unsigned) r;
        return 1;
}

int config_parse_vlanprotocol(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *vlan_protocol = data;

        assert(filename);
        assert(lvalue);

        if (isempty(rvalue)) {
                *vlan_protocol = -1;
                return 1;
        }

        if (STR_IN_SET(rvalue, "802.1ad", "802.1AD"))
                *vlan_protocol = ETH_P_8021AD;
        else if (STR_IN_SET(rvalue, "802.1q", "802.1Q"))
                *vlan_protocol = ETH_P_8021Q;
        else
                return log_syntax_parse_error(unit, filename, line, 0, lvalue, rvalue);

        return 1;
}

int config_parse_hw_addr(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        struct hw_addr_data *hwaddr = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *hwaddr = HW_ADDR_NULL;
                return 1;
        }

        r = parse_hw_addr_full(rvalue, ltype, hwaddr);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1;
}

int config_parse_hw_addrs(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Set **hwaddrs = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *hwaddrs = set_free(*hwaddrs);
                return 1;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                _cleanup_free_ struct hw_addr_data *n = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        return 1;

                n = new(struct hw_addr_data, 1);
                if (!n)
                        return log_oom();

                r = parse_hw_addr_full(word, ltype, n);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Not a valid hardware address, ignoring: %s", word);
                        continue;
                }

                r = set_ensure_consume(hwaddrs, &hw_addr_hash_ops_free, TAKE_PTR(n));
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_ether_addr(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ struct ether_addr *n = NULL;
        struct ether_addr **hwaddr = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *hwaddr = mfree(*hwaddr);
                return 1;
        }

        n = new0(struct ether_addr, 1);
        if (!n)
                return log_oom();

        r = parse_ether_addr(rvalue, n);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        free_and_replace(*hwaddr, n);
        return 1;
}

int config_parse_ether_addrs(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Set **hwaddrs = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Empty assignment resets the list */
                *hwaddrs = set_free(*hwaddrs);
                return 1;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;
                _cleanup_free_ struct ether_addr *n = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r < 0)
                        return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);
                if (r == 0)
                        return 1;

                n = new(struct ether_addr, 1);
                if (!n)
                        return log_oom();

                r = parse_ether_addr(word, n);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Not a valid MAC address, ignoring: %s", word);
                        continue;
                }

                r = set_ensure_consume(hwaddrs, &ether_addr_hash_ops_free, TAKE_PTR(n));
                if (r < 0)
                        return log_oom();
        }
}

int config_parse_in_addr_non_null(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        /* data must be a pointer to struct in_addr or in6_addr, and the type is determined by ltype. */
        struct in_addr *ipv4 = ASSERT_PTR(data);
        struct in6_addr *ipv6 = ASSERT_PTR(data);
        union in_addr_union a;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(IN_SET(ltype, AF_INET, AF_INET6));

        if (isempty(rvalue)) {
                if (ltype == AF_INET)
                        *ipv4 = (struct in_addr) {};
                else
                        *ipv6 = (struct in6_addr) {};
                return 1;
        }

        r = in_addr_from_string(ltype, rvalue, &a);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        if (!in_addr_is_set(ltype, &a)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= cannot be the ANY address, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (ltype == AF_INET)
                *ipv4 = a.in;
        else
                *ipv6 = a.in6;
        return 1;
}

int config_parse_in_addr_data(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        struct in_addr_data *p = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);

        if (isempty(rvalue)) {
                *p = (struct in_addr_data) {};
                return 1;
        }

        r = in_addr_from_string_auto(rvalue, &p->family, &p->address);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1;
}

int config_parse_in_addr_prefix(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype, /* takes boolean, whether we warn about missing prefixlen */
                const char *rvalue,
                void *data,
                void *userdata) {

        struct in_addr_prefix *p = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);

        if (isempty(rvalue)) {
                *p = (struct in_addr_prefix) {};
                return 1;
        }

        r = in_addr_prefix_from_string_auto_full(rvalue, ltype ? PREFIXLEN_REFUSE : PREFIXLEN_FULL, &p->family, &p->address, &p->prefixlen);
        if (r == -ENOANO) {
                r = in_addr_prefix_from_string_auto(rvalue, &p->family, &p->address, &p->prefixlen);
                if (r >= 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "%s=%s is specified without prefix length. Assuming the prefix length is %u. "
                                   "Please specify the prefix length explicitly.", lvalue, rvalue, p->prefixlen);
        }
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1;
}

int config_parse_unsigned_bounded(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                const char *rvalue,
                unsigned min,
                unsigned max,
                bool ignoring,
                unsigned *ret) {

        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(ret);

        r = safe_atou_bounded(rvalue, min, max, ret);
        if (r == -ERANGE) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid '%s=%s', allowed range is %u..%u%s.",
                           lvalue, rvalue, min, max, ignoring ? ", ignoring" : "");
                return ignoring ? 0 : r;
        }
        if (r < 0)
                return log_syntax_parse_error_full(unit, filename, line, r, /* critical = */ !ignoring, lvalue, rvalue);

        return 1;  /* Return 1 if something was set */
}

int config_parse_calendar(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        CalendarSpec **cr = data;
        _cleanup_(calendar_spec_freep) CalendarSpec *c = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *cr = calendar_spec_free(*cr);
                return 1;
        }

        r = calendar_spec_from_string(rvalue, &c);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        free_and_replace_full(*cr, c, calendar_spec_free);
        return 1;
}

DEFINE_CONFIG_PARSE(config_parse_percent, parse_percent);
DEFINE_CONFIG_PARSE(config_parse_permyriad, parse_permyriad);
DEFINE_CONFIG_PARSE_PTR(config_parse_sec_fix_0, parse_sec_fix_0, usec_t);

int config_parse_timezone(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **tz = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *tz = mfree(*tz);
                return 1;
        }

        r = verify_timezone(rvalue, LOG_WARNING);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        r = free_and_strdup_warn(tz, rvalue);
        if (r < 0)
                return r;

        return 1;
}

int config_parse_ip_protocol(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint8_t *proto = ASSERT_PTR(data);
        int r;

        r = isempty(rvalue) ? 0 : parse_ip_protocol_full(rvalue, /* relaxed= */ ltype);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        if (r > UINT8_MAX) {
                /* linux/fib_rules.h and linux/fou.h define the netlink field as one byte, so we need to
                 * reject protocols numbers that don't fit in one byte. */
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid '%s=%s', allowed range is 0..255, ignoring.",
                           lvalue, rvalue);
                return 0;
        }

        *proto = r;
        return 1; /* done. */
}

int config_parse_loadavg(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        loadavg_t *i = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = parse_permyriad(rvalue);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        r = store_loadavg_fixed_point(r / 100, r % 100, i);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 1; /* done. */
}
