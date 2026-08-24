/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "constants.h"
#include "creds-util.h"
#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "errno-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "path-util.h"
#include "resolved-manager.h"
#include "resolved-static-records.h"
#include "set.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

/* This implements a mechanism to extend what systemd-resolved resolves locally, via .rr drop-ins in
 * {/etc,/run,/usr/local/lib,/usr/lib}/systemd/resolve/static.d/. These files are in JSON format, and are RR
 * serializations, that match the usual way we serialize RRs to JSON.
 *
 * Note that this deliberately doesn't use the (probably more user-friendly) classic DNS zone file format,
 * to keep things a bit simpler, and symmetric to the places we currently already generate JSON
 * serializations of DNS RRs. Also note the semantics are different from DNS zone file format, for example
 * regarding delegation (i.e. the RRs defined here have no effect on subdomains), which is probably nicer for
 * one-off mappings of domains to specific resources. Or in other words, this is supposed to be a drop-in
 * based alternative to /etc/hosts, not one to DNS zone files. (The JSON format is also a lot more
 * extensible to us, for example we could teach it to map certain lookups to specific DNS errors, or extend
 * it so that subdomains always get NXDOMAIN or similar).
 *
 * (That said, if there's a good reason, we can also support *.zone files too one day).
 */

/* Recheck static records at most once every 2s */
#define STATIC_RECORDS_RECHECK_USEC (2*USEC_PER_SEC)

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                answer_by_name_hash_ops,
                char,
                dns_name_hash_func,
                dns_name_compare_func,
                DnsAnswer,
                dns_answer_unref);

static int load_static_record_file_item(sd_json_variant *rj, const char *source, Hashmap **records) {
        int r;

        assert(records);

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        r = dns_resource_record_from_json(rj, &rr);
        if (r < 0)
                return log_error_errno(r, "Failed to parse DNS record from %s: %m", source);

        _cleanup_(dns_answer_unrefp) DnsAnswer *a =
                hashmap_remove(*records, dns_resource_key_name(rr->key));

        r = dns_answer_add_extend_full(&a, rr, /* ifindex= */ 0, DNS_ANSWER_AUTHENTICATED, /* rrsig= */ NULL, /* until= */ USEC_INFINITY);
        if (r < 0)
                return log_error_errno(r, "Failed to append RR from %s to DNS answer: %m", source);

        DnsAnswerItem *item = ASSERT_PTR(ordered_set_first(a->items));

        r = hashmap_ensure_put(records, &answer_by_name_hash_ops, dns_resource_key_name(item->rr->key), a);
        if (r < 0)
                return log_error_errno(r, "Failed to add RR to static record set: %m");

        TAKE_PTR(a);

        log_debug("Added static resource record: %s", dns_resource_record_to_string(rr));
        return 1;
}

static int load_static_record_json(sd_json_variant *j, const char *source, Hashmap **records) {
        assert(j);
        assert(source);
        assert(records);

        if (sd_json_variant_is_array(j)) {
                sd_json_variant *i;
                int ret = 0;

                JSON_VARIANT_ARRAY_FOREACH(i, j)
                        RET_GATHER(ret, load_static_record_file_item(i, source, records));
                return ret;
        }

        if (sd_json_variant_is_object(j))
                return load_static_record_file_item(j, source, records);

        log_warning("JSON source %s contains neither array nor object, skipping.", source);
        return 0;
}

static int merge_static_record_overrides(Hashmap **records, Hashmap *source) {
        DnsAnswer *a;
        int r;

        assert(records);

        HASHMAP_FOREACH(a, source) {
                DnsAnswerItem *item = ASSERT_PTR(ordered_set_first(a->items));
                const char *name = dns_resource_key_name(item->rr->key);
                _cleanup_(dns_answer_unrefp) DnsAnswer *copy = dns_answer_ref(a);

                dns_answer_unref(hashmap_remove(*records, name));

                r = hashmap_ensure_put(records, &answer_by_name_hash_ops, name, copy);
                if (r < 0)
                        return r;

                TAKE_PTR(copy);
        }

        return 0;
}

static int add_static_record_stat(Set **stats, const struct stat *st) {
        assert(stats);
        assert(st);

        _cleanup_free_ struct stat *copy = memdup(st, sizeof(*st));
        if (!copy)
                return log_oom();

        if (set_ensure_consume(stats, &inode_unmodified_hash_ops, TAKE_PTR(copy)) < 0)
                return log_oom();

        return 0;
}

static int get_static_record_credential_path(char **ret) {
        _cleanup_free_ char *path = NULL;
        const char *dir;
        int r;

        assert(ret);

        r = get_credentials_dir(&dir);
        if (r < 0)
                return r;

        path = path_join(dir, "network.rr");
        if (!path)
                return log_oom();

        *ret = TAKE_PTR(path);
        return 0;
}

static int static_record_source_stat(
                const char *path,
                Set *old_stats,
                size_t *ret_n_stats,
                bool *ret_changed) {

        struct stat st;
        int r;

        assert(path);
        assert(ret_n_stats);
        assert(ret_changed);

        if (stat(path, &st) < 0) {
                r = -errno;
                if (r == -ENOENT)
                        return 0;

                log_debug_errno(r, "Failed to stat static DNS record source '%s', assuming it changed: %m", path);
                *ret_changed = true;
                return 0;
        }

        (*ret_n_stats)++;
        if (!old_stats || !set_contains(old_stats, &st))
                *ret_changed = true;

        return 0;
}

static int load_static_record_file(const ConfFile *cf, Hashmap **records, Set **stats) {
        int r;

        assert(cf);
        assert(records);
        assert(stats);

        /* Have we seen this file before? Then we might as well skip loading it again, it wouldn't have any
         * additional effect anyway. (Note: masking/overriding has already been applied before we reach this
         * point, here everything is purely additive.) */
        if (set_contains(*stats, &cf->st))
                return 0;

        r = add_static_record_stat(stats, &cf->st);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        unsigned line = 0, column = 0;
        r = sd_json_parse_fd(cf->result, cf->fd, SD_JSON_PARSE_REOPEN_FD, &j, &line, &column);
        if (r < 0) {
                if (line > 0)
                        log_syntax(/* unit= */ NULL, LOG_WARNING, cf->result, line, r, "Failed to parse JSON, skipping: %m");
                else
                        log_warning_errno(r, "Failed to parse JSON file '%s', skipping: %m", cf->result);
                return 0;
        }

        return load_static_record_json(j, cf->result, records);
}

static int load_static_record_path(const char *path, Hashmap **records, Set **stats) {
        _cleanup_(hashmap_freep) Hashmap *source = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        struct stat st;
        unsigned line = 0, column = 0;
        int r;

        assert(path);
        assert(records);
        assert(stats);

        if (stat(path, &st) < 0) {
                r = -errno;
                log_warning_errno(r, "Failed to stat static DNS record file '%s', skipping: %m", path);
                return 0;
        }

        r = add_static_record_stat(stats, &st);
        if (r < 0)
                return r;

        r = sd_json_parse_file(
                        /* f= */ NULL,
                        path,
                        /* flags= */ 0,
                        &j,
                        &line,
                        &column);
        if (r < 0) {
                if (line > 0)
                        log_syntax(/* unit= */ NULL, LOG_WARNING, path, line, r, "Failed to parse JSON, skipping: %m");
                else
                        log_warning_errno(r, "Failed to parse JSON file '%s', skipping: %m", path);
                return 0;
        }

        r = load_static_record_json(j, path, &source);
        if (r < 0)
                return r;

        return merge_static_record_overrides(records, source);
}

static int load_static_record_credential(Hashmap **records, Set **stats) {
        _cleanup_(hashmap_freep) Hashmap *source = NULL;
        _cleanup_free_ char *path = NULL;
        _cleanup_free_ void *data = NULL;
        _cleanup_free_ char *text = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        struct stat st;
        size_t size;
        unsigned line = 0, column = 0;
        int r;

        assert(records);
        assert(stats);

        r = get_static_record_credential_path(&path);
        if (IN_SET(r, -ENXIO, -ENOENT))
                return 0;
        if (r < 0)
                return log_warning_errno(r, "Failed to determine credential network.rr path, ignoring: %m");

        if (stat(path, &st) < 0) {
                r = -errno;
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to stat credential network.rr, ignoring: %m");
                return 0;
        }

        r = add_static_record_stat(stats, &st);
        if (r < 0)
                return r;

        r = read_credential("network.rr", &data, &size);
        if (IN_SET(r, -ENXIO, -ENOENT))
                return 0;
        if (r < 0)
                return log_warning_errno(r, "Failed to read credential network.rr, ignoring: %m");

        if (memchr(data, 0, size))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Credential network.rr contains NUL bytes, ignoring.");

        text = memdup_suffix0(data, size);
        if (!text)
                return log_oom();

        r = sd_json_parse_with_source(text, "credential network.rr", /* flags= */ 0, &j, &line, &column);
        if (r < 0) {
                if (line > 0)
                        log_syntax(/* unit= */ NULL, LOG_WARNING, "credential network.rr", line, r,
                                   "Failed to parse JSON, skipping: %m");
                else
                        log_warning_errno(r, "Failed to parse credential network.rr, skipping: %m");
                return 0;
        }

        r = load_static_record_json(j, "credential network.rr", &source);
        if (r < 0)
                return r;

        return merge_static_record_overrides(records, source);
}

static int manager_static_records_read(Manager *m) {
        int r;

        usec_t ts;
        assert_se(sd_event_now(m->event, CLOCK_BOOTTIME, &ts) >= 0);

        /* See if we checked the static records db recently already */
        if (m->static_records_last != USEC_INFINITY && usec_add(m->static_records_last, STATIC_RECORDS_RECHECK_USEC) > ts)
                return 0;

        m->static_records_last = ts;

        ConfFile **files = NULL;
        size_t n_files = 0;
        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        r = conf_files_list_nulstr_full(
                        ".rr",
                        /* root= */ NULL,
                        CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED|CONF_FILES_WARN,
                        CONF_PATHS_NULSTR("systemd/resolve/static.d/"),
                        &files,
                        &n_files);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate static record drop-ins: %m");

        /* Let's suppress reloads if nothing changed. For that keep the set of inodes from the previous
         * reload around, and see if there are any changes on them. */
        bool reload = !m->static_records_loaded;
        size_t n_stats = n_files;
        if (!reload)
                FOREACH_ARRAY(f, files, n_files)
                        if (!set_contains(m->static_records_stat, &(*f)->st)) {
                                reload = true;
                                break;
                        }

        _cleanup_free_ char *credential_path = NULL;
        if (get_static_record_credential_path(&credential_path) >= 0)
                (void) static_record_source_stat(credential_path,
                                                  m->static_records_loaded ? m->static_records_stat : NULL,
                                                  &n_stats,
                                                  &reload);

        STRV_FOREACH(path, m->static_record_override_paths)
                (void) static_record_source_stat(*path,
                                                  m->static_records_loaded ? m->static_records_stat : NULL,
                                                  &n_stats,
                                                  &reload);

        if (m->static_records_loaded && set_size(m->static_records_stat) != n_stats)
                reload = true;

        if (!reload) {
                log_debug("No static record files changed, not re-reading.");
                return 0;
        }

        _cleanup_(hashmap_freep) Hashmap *records = NULL;
        _cleanup_(hashmap_freep) Hashmap *overrides = NULL;
        _cleanup_(set_freep) Set *stats = NULL;
        FOREACH_ARRAY(f, files, n_files)
                (void) load_static_record_file(*f, &records, &stats);

        (void) load_static_record_credential(&overrides, &stats);
        STRV_FOREACH(path, m->static_record_override_paths)
                (void) load_static_record_path(*path, &overrides, &stats);

        hashmap_free(m->static_records);
        m->static_records = TAKE_PTR(records);
        hashmap_free(m->static_record_overrides);
        m->static_record_overrides = TAKE_PTR(overrides);

        set_free(m->static_records_stat);
        m->static_records_stat = TAKE_PTR(stats);
        m->static_records_loaded = true;

        return 0;
}

int manager_static_records_lookup(Manager *m, DnsQuestion *q, DnsAnswer **answer) {
        int r;

        assert(m);
        assert(q);
        assert(answer);

        if (!m->read_static_records)
                return 0;

        (void) manager_static_records_read(m);

        const char *n = dns_question_first_name(q);
        if (!n)
                return 0;

        DnsAnswer *f = hashmap_get(m->static_records, n);
        if (!f)
                return 0;

        r = dns_answer_extend(answer, f);
        if (r < 0)
                return r;

        return 1;
}

int manager_static_record_overrides_lookup(Manager *m, DnsQuestion *q, DnsAnswer **answer) {
        int r;

        assert(m);
        assert(q);
        assert(answer);

        if (!m->read_static_records)
                return 0;

        (void) manager_static_records_read(m);

        const char *n = dns_question_first_name(q);
        if (!n)
                return 0;

        DnsAnswer *f = hashmap_get(m->static_record_overrides, n);
        if (!f)
                return 0;

        r = dns_answer_extend(answer, f);
        if (r < 0)
                return r;

        return 1;
}

void manager_static_records_flush(Manager *m) {
        assert(m);

        m->static_records = hashmap_free(m->static_records);
        m->static_record_overrides = hashmap_free(m->static_record_overrides);
        m->static_records_stat = set_free(m->static_records_stat);
        m->static_records_loaded = false;
}
