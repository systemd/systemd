#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Dmitry Rozhkov

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "list.h"

typedef struct DnssdService DnssdService;
typedef struct DnssdTxtData DnssdTxtData;

typedef struct Manager Manager;
typedef struct DnsResourceRecord DnsResourceRecord;
typedef struct DnsTxtItem DnsTxtItem;

enum {
        DNS_TXT_ITEM_TEXT,
        DNS_TXT_ITEM_DATA
};

struct DnssdTxtData {
        DnsResourceRecord *rr;

        LIST_HEAD(DnsTxtItem, txt);

        LIST_FIELDS(DnssdTxtData, items);
};

struct DnssdService {
        char *filename;
        char *name;
        char *name_template;
        char *type;
        uint16_t port;
        uint16_t priority;
        uint16_t weight;

        DnsResourceRecord *ptr_rr;
        DnsResourceRecord *srv_rr;

        /* Section 6.8 of RFC 6763 allows having service
         * instances with multiple TXT resource records. */
        LIST_HEAD(DnssdTxtData, txt_data_items);

        Manager *manager;

        bool withdrawn:1;
        uid_t originator;
};

DnssdService *dnssd_service_free(DnssdService *service);
DnssdTxtData *dnssd_txtdata_free(DnssdTxtData *txt_data);
DnssdTxtData *dnssd_txtdata_free_all(DnssdTxtData *txt_data);

DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdService*, dnssd_service_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(DnssdTxtData*, dnssd_txtdata_free);

int dnssd_render_instance_name(DnssdService *s, char **ret_name);
int dnssd_load(Manager *manager);
int dnssd_txt_item_new_from_string(const char *key, const char *value, DnsTxtItem **ret_item);
int dnssd_txt_item_new_from_data(const char *key, const void *value, const size_t size, DnsTxtItem **ret_item);
int dnssd_update_rrs(DnssdService *s);
void dnssd_signal_conflict(Manager *manager, const char *name);
