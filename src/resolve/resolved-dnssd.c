/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "resolved-dnssd.h"
#include "resolved-dns-rr.h"
#include "resolved-manager.h"
#include "resolved-conf.h"
#include "specifier.h"
#include "strv.h"

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

DnssdService *dnssd_service_free(DnssdService *service) {
        if (!service)
                return NULL;

        if (service->manager)
                hashmap_remove(service->manager->dnssd_services, service->name);

        dns_resource_record_unref(service->ptr_rr);
        dns_resource_record_unref(service->srv_rr);

        dnssd_txtdata_free_all(service->txt_data_items);

        free(service->filename);
        free(service->name);
        free(service->type);
        free(service->subtype);
        free(service->name_template);

        return mfree(service);
}

static int dnssd_service_load(Manager *manager, const char *filename) {
        _cleanup_(dnssd_service_freep) DnssdService *service = NULL;
        _cleanup_(dnssd_txtdata_freep) DnssdTxtData *txt_data = NULL;
        char *d;
        const char *dropin_dirname;
        int r;

        assert(manager);
        assert(filename);

        service = new0(DnssdService, 1);
        if (!service)
                return log_oom();

        service->filename = strdup(filename);
        if (!service->filename)
                return log_oom();

        service->name = strdup(basename(filename));
        if (!service->name)
                return log_oom();

        d = endswith(service->name, ".dnssd");
        if (!d)
                return -EINVAL;

        assert(streq(d, ".dnssd"));

        *d = '\0';

        dropin_dirname = strjoina(service->name, ".dnssd.d");

        r = config_parse_many(
                        STRV_MAKE_CONST(filename), DNSSD_SERVICE_DIRS, dropin_dirname, /* root = */ NULL,
                        "Service\0",
                        config_item_perf_lookup, resolved_dnssd_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        service,
                        NULL,
                        NULL);
        if (r < 0)
                return r;

        if (!service->name_template)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s doesn't define service instance name",
                                       service->name);

        if (!service->type)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "%s doesn't define service type",
                                       service->name);

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

        r = hashmap_ensure_put(&manager->dnssd_services, &string_hash_ops, service->name, service);
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
        char *n;

        assert(m->llmnr_hostname);

        n = strdup(m->llmnr_hostname);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int dnssd_render_instance_name(Manager *m, DnssdService *s, char **ret) {
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

        r = conf_files_list_strv(&files, ".dnssd", NULL, 0, DNSSD_SERVICE_DIRS);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate .dnssd files: %m");

        STRV_FOREACH_BACKWARDS(f, files) {
                r = dnssd_service_load(manager, *f);
                if (r < 0)
                        log_warning_errno(r, "Failed to load '%s': %m", *f);
        }

        return 0;
}

int dnssd_update_rrs(DnssdService *s) {
        _cleanup_free_ char *n = NULL, *service_name = NULL, *full_name = NULL, *sub_name = NULL, *selective_name = NULL;
        int r;

        assert(s);
        assert(s->txt_data_items);
        assert(s->manager);

        s->ptr_rr = dns_resource_record_unref(s->ptr_rr);
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

        s->sub_ptr_rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_PTR,
                                                 selective_name);
        if (!s->sub_ptr_rr)
                goto oom;

        s->sub_ptr_rr->ttl = MDNS_DEFAULT_TTL;
        s->sub_ptr_rr->ptr.name = strdup(full_name);
        if (!s->sub_ptr_rr->ptr.name)
                goto oom;

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
        DnssdService *s;
        int r;

        if (sd_bus_is_ready(manager->bus) <= 0)
                return 0;

        HASHMAP_FOREACH(s, manager->dnssd_services) {
                if (s->withdrawn)
                        continue;

                if (dns_name_equal(dns_resource_key_name(s->srv_rr->key), name)) {
                        _cleanup_free_ char *path = NULL;

                        s->withdrawn = true;

                        r = sd_bus_path_encode("/org/freedesktop/resolve1/dnssd", s->name, &path);
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
