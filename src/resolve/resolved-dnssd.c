/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "dns-answer.h"
#include "dns-domain.h"
#include "dns-rr.h"
#include "extract-word.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "log.h"
#include "path-util.h"
#include "resolved-conf.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-zone.h"
#include "resolved-dnssd.h"
#include "resolved-link.h"
#include "resolved-manager.h"
#include "resolved-mdns.h"
#include "set.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

#define DNSSD_SERVICE_DIRS ((const char* const*) CONF_PATHS_STRV("systemd/dnssd"))

DnssdTxtData *dnssd_txtdata_free(DnssdTxtData *txt_data) {
        if (!txt_data)
                return NULL;

        dns_resource_record_unref(txt_data->rr);
        dns_txt_item_free_all(txt_data->txts);

        return mfree(txt_data);
}

DnssdTxtData *dnssd_txtdata_free_all(DnssdTxtData *txt_data) {
        DnssdTxtData *next;

        if (!txt_data)
                return NULL;

        next = txt_data->items_next;

        dnssd_txtdata_free(txt_data);

        return dnssd_txtdata_free_all(next);
}

DnssdRegisteredService *dnssd_registered_service_free(DnssdRegisteredService *service) {
        if (!service)
                return NULL;

        if (service->manager)
                hashmap_remove(service->manager->dnssd_registered_services, service->id);

        sd_bus_track_unref(service->bus_track);

        dns_resource_record_unref(service->ptr_rr);
        dns_resource_record_unref(service->sub_ptr_rr);
        dns_resource_record_unref(service->srv_rr);

        dnssd_txtdata_free_all(service->txt_data_items);

        free(service->path);
        free(service->id);
        free(service->type);
        free(service->subtype);
        free(service->name_template);

        return mfree(service);
}

void dnssd_registered_service_unregister(DnssdRegisteredService *service) {
        int r;

        assert(service);

        Manager *m = ASSERT_PTR(service->manager);

        /* Takes the service out of service: sends goodbye messages for it, removes its RRs from all mDNS
         * zones, and drops it from the manager. Note that this also frees the passed object.
         *
         * The withdrawal is routed through the precise runtime path: it goodbyes the type's
         * enumeration PTR too when this was the last service of its type, leaves records alone
         * that another service still stands behind, splits oversized emissions, and retransmits
         * once per RFC 6762 section 8.3. */

        r = dnssd_registered_service_withdraw(service);
        if (r < 0)
                log_warning_errno(r, "Failed to send goodbye messages, ignoring: %m");

        /* This drops the service from the manager's hashmap, hence the subsequent refresh will not simply
         * add its RRs back. */
        dnssd_registered_service_free(service);

        /* Not while the shutdown withdrawal runs: the refresh force-re-adds the host's address
         * records to the zones, restarting their probes — multicast traffic in the very window
         * every other publication path holds quiet. The zones are torn down with the daemon
         * moments later anyway. */
        if (!m->mdns_withdrawing)
                manager_refresh_rrs(m);
}

void dnssd_registered_service_clear_on_reload(Hashmap *services) {
        DnssdRegisteredService *service;

        HASHMAP_FOREACH(service, services)
                if (service->config_source == RESOLVE_CONFIG_SOURCE_FILE) {
                        hashmap_remove(services, service->id);
                        dnssd_registered_service_free(service);
                }
}

/* The type's enumeration PTR (RFC 6763 section 9). Both the publish and the withdrawal side build
 * it, and the zone can only drop a record it can reconstruct byte for byte, so they share this. */
static int dnssd_registered_service_enumeration_ptr_new(
                DnssdRegisteredService *s,
                DnsResourceRecord **ret) {

        _cleanup_free_ char *service_name = NULL;
        int r;

        assert(s);
        assert(ret);

        r = dns_name_concat(s->type, "local", /* flags= */ 0, &service_name);
        if (r < 0)
                return r;

        return mdns_enumeration_service_ptr_new(service_name, ret);
}

/* Collect the records a registered service publishes — its own plus its type's enumeration PTR
 * (RFC 6763 section 9) — as plain records: the per-scope withdrawal assigns the goodbye flags. */
static int dnssd_registered_service_collect_withdraw_rrs(DnssdRegisteredService *s, DnsAnswer **answer) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *enumeration_rr = NULL;
        DnsResourceRecord *ptr;
        int r;

        assert(s);
        assert(answer);

        r = dnssd_registered_service_enumeration_ptr_new(s, &enumeration_rr);
        if (r < 0)
                return r;

        r = dns_answer_add_extend(answer, enumeration_rr, /* ifindex= */ 0, /* flags= */ 0,
                                  /* rrsig= */ NULL);
        if (r < 0)
                return r;

        FOREACH_ARGUMENT(ptr, s->ptr_rr, s->sub_ptr_rr, s->srv_rr) {
                if (!ptr)
                        continue;

                r = dns_answer_add_extend(answer, ptr, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(items, txt_data, s->txt_data_items) {
                if (!txt_data->rr)
                        continue;

                r = dns_answer_add_extend(answer, txt_data->rr, /* ifindex= */ 0, /* flags= */ 0,
                                          /* rrsig= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Withdraw the given records on every mDNS scope — goodbye on the wire for what each scope's zone
 * actually stands behind, zone removal regardless — and retransmit the emitted records once, one
 * second later: RFC 6762 section 8.3 wants unsolicited announcements, goodbyes included, sent at
 * least twice, and the shutdown path already does so. Best effort by design: failures are logged,
 * the records are going away either way, and peers then age them out over their TTL. */
static void dnssd_withdraw_rrs(Manager *m, DnsAnswer *answer) {
        DnsScope *scope;
        Link *l;
        int r;

        assert(m);

        if (dns_answer_isempty(answer))
                return;

        log_debug("Withdrawing %zu DNS-SD record(s) with a goodbye.", dns_answer_size(answer));

        bool pending = false;

        HASHMAP_FOREACH(l, m->links)
                FOREACH_ARGUMENT(scope, l->mdns_ipv4_scope, l->mdns_ipv6_scope) {
                        if (!scope)
                                continue;

                        r = dns_scope_withdraw_rrs(scope, answer);
                        if (r < 0)
                                log_warning_errno(r, "Failed to withdraw mDNS records, ignoring: %m");

                        pending = pending || !dns_answer_isempty(scope->pending_withdrawals);
                }

        if (pending)
                manager_arm_mdns_withdrawal_retransmit(m);
}

/* Everything the still-registered services publish — their own records plus their types'
 * enumeration PTRs — except the given one: records some other service still stands behind must not
 * be withdrawn along with it. Returned as a set, because the withdrawal tests every candidate
 * against it and a linear answer would make that quadratic in the number of published records. */
static int dnssd_collect_published_rrs(Manager *m, DnssdRegisteredService *except, Set **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *published = NULL;
        _cleanup_set_free_ Set *index = NULL;
        DnssdRegisteredService *s;
        DnsResourceRecord *rr;
        int r;

        assert(m);
        assert(ret);

        HASHMAP_FOREACH(s, m->dnssd_registered_services) {
                if (s == except)
                        continue;

                r = dnssd_registered_service_collect_withdraw_rrs(s, &published);
                if (r < 0)
                        return r;
        }

        DNS_ANSWER_FOREACH(rr, published) {
                /* The hash ops carry a key destructor, so the set owns what it holds — and the
                 * answer these records come from is released on the way out. */
                r = set_ensure_consume(&index, &dns_resource_record_hash_ops, dns_resource_record_ref(rr));
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(index);
        return 0;
}

/* Withdraw the candidate records that no service outside 'except' publishes identically. */
int dnssd_withdraw_filtered(Manager *m, DnsAnswer *candidates, DnssdRegisteredService *except) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *stale = NULL;
        _cleanup_set_free_ Set *published = NULL;
        DnsAnswerItem *item;
        int r;

        assert(m);

        /* The common reload has nothing to withdraw; do not build the published-record index
         * just to filter an empty candidate list against it. */
        if (dns_answer_isempty(candidates))
                return 0;

        r = dnssd_collect_published_rrs(m, except, &published);
        if (r < 0)
                return r;

        DNS_ANSWER_FOREACH_ITEM(item, candidates) {
                if (set_contains(published, item->rr))
                        continue;

                r = dns_answer_add_extend_full(&stale, item->rr, item->ifindex,
                                               item->flags, item->rrsig, item->until);
                if (r < 0)
                        return r;
        }

        dnssd_withdraw_rrs(m, stale);
        return 0;
}

/* Does a registered service other than 'except' still publish its type? The type's enumeration PTR
 * is shared by every instance of the type, so it only goes with the last one. */
static bool dnssd_type_published_elsewhere(Manager *m, DnssdRegisteredService *except) {
        DnssdRegisteredService *s;

        assert(m);
        assert(except);

        HASHMAP_FOREACH(s, m->dnssd_registered_services)
                /* Case-insensitively: DNS names compare that way (RFC 1035 § 2.3.3) and nothing
                 * normalises Type= on the way in, so "_HTTP._tcp" and "_http._tcp" are one type and
                 * share one enumeration PTR. */
                if (s != except && dns_name_equal(s->type, except->type) > 0)
                        return true;

        return false;
}

/* Best-effort fallback: whatever else fails, the service's records must leave the zones — or
 * resolved would keep answering and re-announcing for a service that no longer exists. */
static void dnssd_registered_service_remove_from_zones(DnssdRegisteredService *s) {
        DnsResourceRecord *ptr;
        DnsScope *scope;
        Link *l;

        assert(s);
        assert(s->manager);

        HASHMAP_FOREACH(l, s->manager->links)
                FOREACH_ARGUMENT(scope, l->mdns_ipv4_scope, l->mdns_ipv6_scope) {
                        if (!scope)
                                continue;

                        FOREACH_ARGUMENT(ptr, s->ptr_rr, s->sub_ptr_rr, s->srv_rr)
                                if (ptr)
                                        dns_zone_remove_rr(&scope->zone, ptr);

                        LIST_FOREACH(items, txt_data, s->txt_data_items)
                                if (txt_data->rr)
                                        dns_zone_remove_rr(&scope->zone, txt_data->rr);
                }

        /* And the type's enumeration PTR (RFC 6763 § 9) once this was the last instance of the type,
         * or the zone would keep answering type enumerations with a type nothing serves. Building it
         * takes an allocation -- the very thing that may have just failed -- so this stays best
         * effort like the rest of the fallback. */
        if (!dnssd_type_published_elsewhere(s->manager, s)) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *enumeration_rr = NULL;

                if (dnssd_registered_service_enumeration_ptr_new(s, &enumeration_rr) >= 0)
                        HASHMAP_FOREACH(l, s->manager->links)
                                FOREACH_ARGUMENT(scope, l->mdns_ipv4_scope, l->mdns_ipv6_scope)
                                        if (scope)
                                                dns_zone_remove_rr(&scope->zone, enumeration_rr);
        }
}

int dnssd_registered_service_withdraw(DnssdRegisteredService *s) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        int r;

        assert(s);
        assert(s->manager);

        r = dnssd_registered_service_collect_withdraw_rrs(s, &answer);
        if (r < 0) {
                dnssd_registered_service_remove_from_zones(s);
                return r;
        }

        r = dnssd_withdraw_filtered(s->manager, answer, s);
        if (r < 0)
                dnssd_registered_service_remove_from_zones(s);

        return r;
}

/* Snapshot the records of all file-sourced registered services, for reconciling a reload: taken
 * before the services are cleared, withdrawn — filtered against what came back — afterwards. */
int dnssd_snapshot_file_service_rrs(Manager *m, DnsAnswer **ret) {
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnssdRegisteredService *s;
        int r;

        assert(m);
        assert(ret);

        HASHMAP_FOREACH(s, m->dnssd_registered_services) {
                if (s->config_source != RESOLVE_CONFIG_SOURCE_FILE)
                        continue;

                r = dnssd_registered_service_collect_withdraw_rrs(s, &answer);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(answer);
        return 0;
}

static int dnssd_id_from_path(const char *path, char **ret_id) {
        int r;

        assert(path);
        assert(ret_id);

        _cleanup_free_ char *fn = NULL;
        r = path_extract_filename(path, &fn);
        if (r < 0)
                return r;

        char *d = endswith(fn, ".dnssd");
        if (!d)
                return -EINVAL;

        *d = '\0';

        *ret_id = TAKE_PTR(fn);
        return 0;
}

static int dnssd_registered_service_load(Manager *manager, const char *path) {
        _cleanup_(dnssd_registered_service_freep) DnssdRegisteredService *service = NULL;
        _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;
        _cleanup_free_ char *dropin_dirname = NULL;
        int r;

        assert(manager);
        assert(path);

        service = new0(DnssdRegisteredService, 1);
        if (!service)
                return log_oom();

        service->path = strdup(path);
        if (!service->path)
                return log_oom();

        r = dnssd_id_from_path(path, &service->id);
        if (r < 0)
                return log_error_errno(r, "Failed to extract DNS-SD service id from filename: %m");

        dropin_dirname = strjoin(service->id, ".dnssd.d");
        if (!dropin_dirname)
                return log_oom();

        r = config_parse_many(
                        STRV_MAKE_CONST(path),
                        DNSSD_SERVICE_DIRS,
                        dropin_dirname,
                        "Service\0",
                        config_item_perf_lookup, resolved_dnssd_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        service);
        if (r < 0)
                return r;

        if (!service->name_template)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s doesn't define service instance name",
                                       service->id);

        if (!service->type)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s doesn't define service type",
                                       service->id);

        if (!service->txt_data_items) {
                txt_data = new0(DnssdTxtData, 1);
                if (!txt_data)
                        return log_oom();

                r = dns_txt_item_new_empty(&txt_data->txts);
                if (r < 0)
                        return r;

                LIST_PREPEND(items, service->txt_data_items, txt_data);
                TAKE_PTR(txt_data);
        }

        r = hashmap_ensure_put(&manager->dnssd_registered_services, &string_hash_ops, service->id, service);
        if (r < 0)
                return r;

        service->manager = manager;

        r = dnssd_update_rrs(service);
        if (r < 0)
                return r;

        TAKE_PTR(service);

        return 0;
}

static int specifier_dnssd_hostname(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const Manager *m = ASSERT_PTR(userdata);

        assert(m->llmnr_hostname);

        return strdup_to(ret, m->llmnr_hostname);
}

int dnssd_render_instance_name(Manager *m, DnssdRegisteredService *s, char **ret) {
        static const Specifier specifier_table[] = {
                { 'a', specifier_architecture,   NULL },
                { 'b', specifier_boot_id,        NULL },
                { 'B', specifier_os_build_id,    NULL },
                { 'H', specifier_dnssd_hostname, NULL },
                { 'm', specifier_machine_id,     NULL },
                { 'o', specifier_os_id,          NULL },
                { 'v', specifier_kernel_release, NULL },
                { 'w', specifier_os_version_id,  NULL },
                { 'W', specifier_os_variant_id,  NULL },
                {}
        };
        _cleanup_free_ char *name = NULL;
        int r;

        assert(m);
        assert(s);
        assert(s->name_template);

        r = specifier_printf(s->name_template, DNS_LABEL_MAX, specifier_table, NULL, m, &name);
        if (r < 0)
                return log_debug_errno(r, "Failed to replace specifiers: %m");

        if (!dns_service_name_is_valid(name))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Service instance name '%s' is invalid.",
                                       name);

        if (ret)
                *ret = TAKE_PTR(name);

        return 0;
}

int dnssd_load(Manager *manager) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(manager);

        if (manager->mdns_support != RESOLVE_SUPPORT_YES)
                return 0;

        r = conf_files_list_strv(&files, ".dnssd", /* root= */ NULL, CONF_FILES_WARN, DNSSD_SERVICE_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate .dnssd files: %m");

        STRV_FOREACH_BACKWARDS(f, files) {
                r = dnssd_registered_service_load(manager, *f);
                if (r < 0)
                        log_warning_errno(r, "Failed to load '%s': %m", *f);
        }

        return 0;
}

int dnssd_update_rrs(DnssdRegisteredService *s) {
        _cleanup_free_ char *n = NULL, *service_name = NULL, *full_name = NULL, *sub_name = NULL, *selective_name = NULL;
        int r;

        assert(s);
        assert(s->txt_data_items);
        assert(s->manager);

        s->ptr_rr = dns_resource_record_unref(s->ptr_rr);
        s->sub_ptr_rr = dns_resource_record_unref(s->sub_ptr_rr);
        s->srv_rr = dns_resource_record_unref(s->srv_rr);
        LIST_FOREACH(items, txt_data, s->txt_data_items)
                txt_data->rr = dns_resource_record_unref(txt_data->rr);

        r = dnssd_render_instance_name(s->manager, s, &n);
        if (r < 0)
                return r;

        r = dns_name_concat(s->type, "local", 0, &service_name);
        if (r < 0)
                return r;
        r = dns_name_concat(n, service_name, 0, &full_name);
        if (r < 0)
                return r;
        if (s->subtype) {
                r = dns_name_concat("_sub", service_name, 0, &sub_name);
                if (r < 0)
                        return r;
                r = dns_name_concat(s->subtype, sub_name, 0, &selective_name);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(items, txt_data, s->txt_data_items) {
                txt_data->rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_TXT,
                                                            full_name);
                if (!txt_data->rr)
                        goto oom;

                txt_data->rr->ttl = MDNS_DEFAULT_TTL;
                txt_data->rr->txt.items = dns_txt_item_copy(txt_data->txts);
                if (!txt_data->rr->txt.items)
                        goto oom;
        }

        s->ptr_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR,
                                                 service_name);
        if (!s->ptr_rr)
                goto oom;

        s->ptr_rr->ttl = MDNS_DEFAULT_TTL;
        s->ptr_rr->ptr.name = strdup(full_name);
        if (!s->ptr_rr->ptr.name)
                goto oom;

        if (selective_name) {
                s->sub_ptr_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR, selective_name);
                if (!s->sub_ptr_rr)
                        goto oom;

                s->sub_ptr_rr->ttl = MDNS_DEFAULT_TTL;
                s->sub_ptr_rr->ptr.name = strdup(full_name);
                if (!s->sub_ptr_rr->ptr.name)
                        goto oom;
        }

        s->srv_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_SRV,
                                                 full_name);
        if (!s->srv_rr)
                goto oom;

        s->srv_rr->ttl = MDNS_DEFAULT_TTL;
        s->srv_rr->srv.priority = s->priority;
        s->srv_rr->srv.weight = s->weight;
        s->srv_rr->srv.port = s->port;
        s->srv_rr->srv.name = strdup(s->manager->mdns_hostname);
        if (!s->srv_rr->srv.name)
                goto oom;

        return 0;

oom:
        LIST_FOREACH(items, txt_data, s->txt_data_items)
                txt_data->rr = dns_resource_record_unref(txt_data->rr);
        s->ptr_rr = dns_resource_record_unref(s->ptr_rr);
        s->sub_ptr_rr = dns_resource_record_unref(s->sub_ptr_rr);
        s->srv_rr = dns_resource_record_unref(s->srv_rr);
        return -ENOMEM;
}

int dnssd_txt_item_new_from_string(const char *key, const char *value, DnsTxtItem **ret_item) {
        size_t length;
        DnsTxtItem *i;

        assert(ret_item);

        length = strlen(key);

        if (!isempty(value))
                length += strlen(value) + 1; /* length of value plus '=' */

        i = malloc0(offsetof(DnsTxtItem, data) + length + 1); /* for safety reasons we add an extra NUL byte */
        if (!i)
                return -ENOMEM;

        memcpy(i->data, key, strlen(key));
        if (!isempty(value)) {
                memcpy(i->data + strlen(key), "=", 1);
                memcpy(i->data + strlen(key) + 1, value, strlen(value));
        }
        i->length = length;

        *ret_item = TAKE_PTR(i);

        return 0;
}

int dnssd_txt_item_new_from_data(const char *key, const void *data, const size_t size, DnsTxtItem **ret_item) {
        size_t length;
        DnsTxtItem *i;

        assert(ret_item);

        length = strlen(key);

        if (size > 0)
                length += size + 1; /* size of date plus '=' */

        i = malloc0(offsetof(DnsTxtItem, data) + length + 1); /* for safety reasons we add an extra NUL byte */
        if (!i)
                return -ENOMEM;

        memcpy(i->data, key, strlen(key));
        if (size > 0) {
                memcpy(i->data + strlen(key), "=", 1);
                memcpy(i->data + strlen(key) + 1, data, size);
        }
        i->length = length;

        *ret_item = TAKE_PTR(i);

        return 0;
}

int dnssd_signal_conflict(Manager *manager, const char *name) {
        DnssdRegisteredService *s;
        int r;

        if (sd_bus_is_ready(manager->bus) <= 0)
                return 0;

        HASHMAP_FOREACH(s, manager->dnssd_registered_services) {
                if (s->withdrawn)
                        continue;

                if (dns_name_equal(dns_resource_key_name(s->srv_rr->key), name) > 0) {
                        _cleanup_free_ char *path = NULL;

                        s->withdrawn = true;

                        r = sd_bus_path_encode("/org/freedesktop/resolve1/dnssd", s->id, &path);
                        if (r < 0)
                                return log_error_errno(r, "Can't get D-BUS object path: %m");

                        r = sd_bus_emit_signal(manager->bus,
                                               path,
                                               "org.freedesktop.resolve1.DnssdService",
                                               "Conflicted",
                                               NULL);
                        if (r < 0)
                                return log_error_errno(r, "Cannot emit signal: %m");

                        break;
                }
        }

        return 0;
}

int config_parse_dnssd_name(
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

        static const Specifier specifier_table[] = {
                { 'a', specifier_architecture,    NULL },
                { 'b', specifier_boot_id,         NULL },
                { 'B', specifier_os_build_id,     NULL },
                { 'H', specifier_hostname,        NULL }, /* We will use specifier_dnssd_hostname(). */
                { 'm', specifier_machine_id,      NULL },
                { 'o', specifier_os_id,           NULL },
                { 'v', specifier_kernel_release,  NULL },
                { 'w', specifier_os_version_id,   NULL },
                { 'W', specifier_os_variant_id,   NULL },
                {}
        };
        DnssdRegisteredService *s = ASSERT_PTR(userdata);
        _cleanup_free_ char *name = NULL;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                s->name_template = mfree(s->name_template);
                return 0;
        }

        r = specifier_printf(rvalue, DNS_LABEL_MAX, specifier_table, NULL, NULL, &name);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid service instance name template '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        if (!dns_service_name_is_valid(name)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Service instance name template '%s' renders to invalid name '%s'. Ignoring assignment.",
                           rvalue, name);
                return 0;
        }

        return free_and_strdup_warn(&s->name_template, rvalue);
}

int config_parse_dnssd_type(
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

        DnssdRegisteredService *s = ASSERT_PTR(userdata);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                s->type = mfree(s->type);
                return 0;
        }

        if (!dnssd_srv_type_is_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Service type is invalid. Ignoring.");
                return 0;
        }

        r = free_and_strdup(&s->type, rvalue);
        if (r < 0)
                return log_oom();

        return 0;
}

int config_parse_dnssd_subtype(
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

        DnssdRegisteredService *s = ASSERT_PTR(userdata);

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                s->subtype = mfree(s->subtype);
                return 0;
        }

        if (!dns_subtype_name_is_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Service subtype is invalid. Ignoring.");
                return 0;
        }

        return free_and_strdup_warn(&s->subtype, rvalue);
}

int config_parse_dnssd_txt(
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

        _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;
        DnssdRegisteredService *s = ASSERT_PTR(userdata);
        DnsTxtItem *last = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                /* Flush out collected items */
                s->txt_data_items = dnssd_txtdata_free_all(s->txt_data_items);
                return 0;
        }

        txt_data = new0(DnssdTxtData, 1);
        if (!txt_data)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *word = NULL, *key = NULL, *value = NULL;
                _cleanup_free_ void *decoded = NULL;
                size_t length = 0;
                DnsTxtItem *i;
                int r;

                r = extract_first_word(&rvalue, &word, NULL,
                                       EXTRACT_UNQUOTE|EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX);
                if (r == 0)
                        break;
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }

                r = split_pair(word, "=", &key, &value);
                if (r == -ENOMEM)
                        return log_oom();
                if (r == -EINVAL)
                        key = TAKE_PTR(word);

                if (!ascii_is_valid(key)) {
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "Invalid key, ignoring: %s", key);
                        continue;
                }

                switch (ltype) {

                case DNS_TXT_ITEM_DATA:
                        if (value) {
                                r = unbase64mem(value, &decoded, &length);
                                if (r == -ENOMEM)
                                        return log_oom();
                                if (r < 0) {
                                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                                   "Invalid base64 encoding, ignoring: %s", value);
                                        continue;
                                }
                        }

                        r = dnssd_txt_item_new_from_data(key, decoded, length, &i);
                        if (r < 0)
                                return log_oom();
                        break;

                case DNS_TXT_ITEM_TEXT:
                        r = dnssd_txt_item_new_from_string(key, value, &i);
                        if (r < 0)
                                return log_oom();
                        break;

                default:
                        assert_not_reached();
                }

                LIST_INSERT_AFTER(items, txt_data->txts, last, i);
                last = i;
        }

        if (txt_data->txts) {
                LIST_PREPEND(items, s->txt_data_items, txt_data);
                TAKE_PTR(txt_data);
        }

        return 0;
}
