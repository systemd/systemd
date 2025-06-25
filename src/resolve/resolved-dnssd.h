/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "list.h"
#include "resolved-conf.h"
#include "resolved-forward.h"

enum {
        DNS_TXT_ITEM_TEXT,
        DNS_TXT_ITEM_DATA,
};

typedef struct DnssdTxtData {
        DnsResourceRecord *rr;

        LIST_HEAD(DnsTxtItem, txts);

        LIST_FIELDS(DnssdTxtData, items);
} DnssdTxtData;

typedef struct DnssdService {
        char *path;
        char *id;
        char *name_template;
        char *type;
        char *subtype;
        uint16_t port;
        uint16_t priority;
        uint16_t weight;

        DnsResourceRecord *ptr_rr;
        DnsResourceRecord *sub_ptr_rr;
        DnsResourceRecord *srv_rr;

        /* Section 6.8 of RFC 6763 allows having service
         * instances with multiple TXT resource records. */
        LIST_HEAD(DnssdTxtData, txt_data_items);

        Manager *manager;

        /* Services registered via D-Bus are not removed on reload */
        ResolveConfigSource config_source;

        bool withdrawn:1;
        uid_t originator;
} DnssdService;

DnssdService *dnssd_service_free(DnssdService *service);
DnssdTxtData *dnssd_txtdata_free(DnssdTxtData *txt_data);
DnssdTxtData *dnssd_txtdata_free_all(DnssdTxtData *txt_data);
void dnssd_service_clear_on_reload(Hashmap *services);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdService*, dnssd_service_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdTxtData*, dnssd_txtdata_free);

int dnssd_render_instance_name(Manager *m, DnssdService *s, char **ret);
int dnssd_load(Manager *manager);
int dnssd_txt_item_new_from_string(const char *key, const char *value, DnsTxtItem **ret_item);
int dnssd_txt_item_new_from_data(const char *key, const void *value, const size_t size, DnsTxtItem **ret_item);
int dnssd_update_rrs(DnssdService *s);
int dnssd_signal_conflict(Manager *manager, const char *name);

const struct ConfigPerfItem* resolved_dnssd_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_service_name);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_service_subtype);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_service_type);
CONFIG_PARSER_PROTOTYPE(config_parse_dnssd_txt);
