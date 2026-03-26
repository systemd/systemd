/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "constants.h"
#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "resolved-manager.h"
#include "resolved-static-records.h"
#include "set.h"
#include "stat-util.h"

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

static int load_static_record_file_item(sd_json_variant *rj, Hashmap **records) {
        int r;

        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        r = dns_resource_record_from_json(rj, &rr);
        if (r < 0)
                return log_error_errno(r, "Failed to parse DNS record from JSON: %m");

        _cleanup_(dns_answer_unrefp) DnsAnswer *a =
                hashmap_remove(*records, dns_resource_key_name(rr->key));

        r = dns_answer_add_extend_full(&a, rr, /* ifindex= */ 0, DNS_ANSWER_AUTHENTICATED, /* rrsig= */ NULL, /* until= */ USEC_INFINITY);
        if (r < 0)
                return log_error_errno(r, "Failed to append RR to DNS answer: %m");

        DnsAnswerItem *item = ASSERT_PTR(ordered_set_first(a->items));

        r = hashmap_ensure_put(records, &answer_by_name_hash_ops, dns_resource_key_name(item->rr->key), a);
        if (r < 0)
                return log_error_errno(r, "Failed to add RR to static record set: %m");

        TAKE_PTR(a);

        log_debug("Added static resource record: %s", dns_resource_record_to_string(rr));
        return 1;
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

        _cleanup_free_ struct stat *st_copy = memdup(&cf->st, sizeof(cf->st));
        if (!st_copy)
                return log_oom();

        if (set_ensure_consume(stats, &inode_unmodified_hash_ops, TAKE_PTR(st_copy)) < 0)
                return log_oom();

        _cleanup_fclose_ FILE *f = NULL;
        r = xfopenat(cf->fd, /* path= */ NULL, "re", /* open_flags= */ 0, &f);
        if (r < 0) {
                log_warning_errno(r, "Failed to open '%s', skipping: %m", cf->result);
                return 0;
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *j = NULL;
        unsigned line = 0, column = 0;
        r = sd_json_parse_file(f, cf->result, /* flags= */ 0, &j, &line, &column);
        if (r < 0) {
                if (line > 0)
                        log_syntax(/* unit= */ NULL, LOG_WARNING, cf->result, line, r, "Failed to parse JSON, skipping: %m");
                else
                        log_warning_errno(r, "Failed to parse JSON file '%s', skipping: %m", cf->result);
                return 0;
        }

        if (sd_json_variant_is_array(j)) {
                sd_json_variant *i;
                int ret = 0;
                JSON_VARIANT_ARRAY_FOREACH(i, j)
                        RET_GATHER(ret, load_static_record_file_item(i, records));
                if (ret < 0)
                        return ret;
        } else if (sd_json_variant_is_object(j)) {
                r = load_static_record_file_item(j, records);
                if (r < 0)
                        return r;
        } else {
                log_warning("JSON file '%s' contains neither array nor object, skipping.", cf->result);
                return 0;
        }

        return 1;
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
        CLEANUP_ARRAY(files, n_files, conf_file_free_many);

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
        bool reload;
        if (set_size(m->static_records_stat) != n_files)
                reload = true;
        else {
                reload = false;
                FOREACH_ARRAY(f, files, n_files)
                        if (!set_contains(m->static_records_stat, &(*f)->st)) {
                                reload = true;
                                break;
                        }
        }

        if (!reload) {
                log_debug("No static record files changed, not re-reading.");
                return 0;
        }

        _cleanup_(hashmap_freep) Hashmap *records = NULL;
        _cleanup_(set_freep) Set *stats = NULL;
        FOREACH_ARRAY(f, files, n_files)
                (void) load_static_record_file(*f, &records, &stats);

        hashmap_free(m->static_records);
        m->static_records = TAKE_PTR(records);

        set_free(m->static_records_stat);
        m->static_records_stat = TAKE_PTR(stats);

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

void manager_static_records_flush(Manager *m) {
        assert(m);

        m->static_records = hashmap_free(m->static_records);
        m->static_records_stat = set_free(m->static_records_stat);
}
