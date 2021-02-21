/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <curl/curl.h>

#include "cloud-provider-link.h"

#include "alloc-util.h"
#include "cloud-provider-manager.h"
#include "ether-addr-util.h"
#include "fileio.h"
#include "json.h"
#include "network-cloud-azure.h"
#include "network-cloud-util.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "strv.h"
#include "virt.h"

void *azure_cloud_metadata_free(AzureCloudMetadata *m) {
        if (!m)
                return NULL;

        m->address = ordered_hashmap_free_free(m->address);
        return mfree(m);
}

static int azure_parse_ip_address(JsonVariant *v, AzureCloudMetadata *az) {
        JsonVariant *e;
        int r;

        assert(v);
        assert(az);

        r = ordered_hashmap_ensure_allocated(&az->address, &trivial_hash_ops);
        if (r < 0)
                return r;

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                _cleanup_free_ AzureCloudIPSet *c = NULL;
                JsonVariant *w;

                c = new0(AzureCloudIPSet, 1);
                if (!c)
                        return log_oom();

                w = json_variant_by_key(e, "privateIpAddress");
                if (!isempty(json_variant_string(w))) {
                        r = in_addr_from_string(AF_INET, json_variant_string(w), &c->private_ip);
                        if (r < 0)
                                return r;
                }

                w = json_variant_by_key(e, "publicIpAddress");
                if (!isempty(json_variant_string(w))) {
                        r = in_addr_from_string(AF_INET, json_variant_string(w), &c->public_ip);
                        if (r < 0)
                                return 0;
                }

                r = ordered_hashmap_put(az->address, c, c);
                if (r < 0)
                        return r;

                TAKE_PTR(c);
        }

        return 0;
}

static int azure_parse_ip_subnet(JsonVariant *v, AzureCloudMetadata *az) {
        JsonVariant *e;
        int r;

        assert(v);
        assert(az);

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                JsonVariant *w;

                w = json_variant_by_key(e, "address");
                if (w) {
                        r = in_addr_from_string(AF_INET, json_variant_string(w), &az->subnet);
                        if (r < 0)
                                return 0;
                }

                w = json_variant_by_key(e, "prefix");
                if (w) {
                        uint16_t k;

                        r = safe_atou16(json_variant_string(w), &k);
                        if (r < 0)
                                return r;

                        az->prefixlen = k;
                }
        }

        return 0;
}

static int azure_parse_ip_subnet_object(JsonVariant *a, NetworkCloudMetaData *c) {
        JsonVariant *v;
        const char *k;
        int r;

        assert(a);
        assert(c);

        JSON_VARIANT_OBJECT_FOREACH(k, v, a) {
                _cleanup_free_ AzureCloudMetadata *az = NULL;

                (void) k;

                az = new0(AzureCloudMetadata, 1);
                if (!az)
                        return -ENOMEM;

                r = azure_parse_ip_address(v, az);
                if (r < 0)
                        return r;

                r = azure_parse_ip_subnet(v, az);
                if (r < 0)
                        return r;

                r = ordered_hashmap_ensure_put(&c->ipv4, &trivial_hash_ops, az, az);
                if (r < 0)
                        return r;

                TAKE_PTR(az);
        }

        return 0;
}

static int azure_parse_mac_array(JsonVariant *a, NetworkCloudMetaData *c) {
        JsonVariant *e;
        int r;

        assert(a);

        JSON_VARIANT_ARRAY_FOREACH(e, a) {
                JsonVariant *d;

                d = json_variant_by_key(e, "macAddress");
                if (d) {
                        r = ether_addr_from_string_full(json_variant_string(d), &c->mac);
                        if (r < 0)
                                return r;
                }

                d = json_variant_by_key(e, "ipv4");
                if (d)
                        return azure_parse_ip_subnet_object(d, c);
        }

        return 0;
}

int azure_parse_json_object(NetworkCloudProvider *m, JsonVariant *j) {
        JsonVariant *v;
        const char *k;
        int r;

        assert(m);
        assert(j);

        JSON_VARIANT_OBJECT_FOREACH(k, v, j) {
                _cleanup_free_ NetworkCloudMetaData *c = NULL;

                (void) k;

                r = network_cloud_metadata_new(&c);
                if (r < 0)
                        return r;

                if (json_variant_is_array(v)) {
                        r = azure_parse_mac_array(v, c);
                        if (r < 0)
                                return r;
                }

                r = ordered_hashmap_ensure_put(&m->interfaces_by_mac, &ether_addr_hash_ops, &c->mac, c);
                if (r < 0)
                        return r;

                TAKE_PTR(c);
        }

        return 0;
}

int azure_acquire_cloud_metadata_from_imds(NetworkCloudProvider **ret) {
        _cleanup_(curl_slist_free_allp) struct curl_slist *request_header = NULL;
        _cleanup_(network_cloud_provider_freep) NetworkCloudProvider *m = NULL;
        _cleanup_(curl_easy_cleanupp) CURL *curl = NULL;
        _cleanup_free_ char *url = NULL;
        int r;

        assert(ret);

        r = network_cloud_provider_new(CLOUD_PROVIDER_AZURE, &m);
        if (r < 0)
                return r;

        curl = curl_easy_init();
        if (!curl)
                return -ENOSR;

        url = strjoin("http://", AZURE_IMDS_REST_ENDPOINT, AZURE_NETWORK_METADATA_URL_BASE, AZURE_API_VERSION);
        if (!url)
                return log_oom();

        if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK)
                return -EIO;

        request_header = curl_slist_append(request_header, "Metadata:true");
        if (!request_header)
                return log_oom();

        if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_header) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, network_cloud_meta_data_write_callback) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, m) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5) != CURLE_OK)
                return -EIO;

        if (curl_easy_perform(curl) != CURLE_OK)
                return -EIO;

        *ret = TAKE_PTR(m);
        return 0;
}

static void *azure_normalized_link_info_free(AzureNormalizedLinkInfo *n) {
        if (!n)
                return NULL;

        strv_free(n->ipv4_private_ips);
        strv_free(n->ipv4_public_ips);
        return mfree(n);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(AzureNormalizedLinkInfo*, azure_normalized_link_info_free);

static int azure_cloud_network_data_get_normalized(NetworkCloudProvider *c,
                                                   Link *link,
                                                   AzureNormalizedLinkInfo **ret) {

        _cleanup_(azure_normalized_link_info_freep) AzureNormalizedLinkInfo *n = NULL;
        NetworkCloudMetaData *d;
        AzureCloudMetadata *i;
        int r;

        assert(c);
        assert(c->interfaces_by_mac);
        assert(link);

        d = ordered_hashmap_get(c->interfaces_by_mac, &link->mac_address);
        if (!d)
                return -ENODATA;

        n = new(AzureNormalizedLinkInfo, 1);
        if (!n)
                return log_oom();

        *n = (AzureNormalizedLinkInfo) {
                .family = AF_INET,
        };

        /* first parse the prefixlen and subnet */
        ORDERED_HASHMAP_FOREACH(i, d->ipv4) {
                n->subnet = i->subnet;
                n->prefixlen = i->prefixlen;
        }

        ORDERED_HASHMAP_FOREACH(i, d->ipv4) {
                _cleanup_strv_free_ char **public_ips = NULL, **private_ips = NULL;
                AzureCloudIPSet *k;

                ORDERED_HASHMAP_FOREACH(k, i->address) {
                        _cleanup_free_ char *public = NULL, *private = NULL;

                        if (in_addr_is_null(AF_INET, &k->public_ip) == 0) {
                                r = in_addr_to_string(AF_INET, &k->public_ip, &public);
                                if (r < 0)
                                        continue;

                                r = strv_extend(&public_ips, public);
                                if (r < 0)
                                        return log_oom();
                        }

                        if (in_addr_is_null(AF_INET, &k->private_ip) == 0) {
                                r = in_addr_to_string(AF_INET, &k->private_ip, &private);
                                if (r < 0)
                                        continue;

                                r = strv_extend(&private_ips, private);
                                if (r < 0)
                                        return log_oom();
                        }
                }

                if (public_ips)
                        n->ipv4_public_ips = TAKE_PTR(public_ips);

                if (private_ips)
                        n->ipv4_private_ips = TAKE_PTR(private_ips);
        }

        *ret = TAKE_PTR(n);
        return 0;
}

int azure_link_save(Link *l, FILE *f) {
        _cleanup_(azure_normalized_link_info_freep) AzureNormalizedLinkInfo *info = NULL;
        bool space = false;
        int r;

        assert(l);
        assert(l->manager);
        assert(l->manager->cloud_manager);
        assert(f);

        r = azure_cloud_network_data_get_normalized(l->manager->cloud_manager, l, &info);
        if (r < 0)
                return r;

        log_debug("Saving Azure Cloud metadata for link '%s'", l->ifname);

        fprintf(f, "%s=", "AZURE_IPV4_PRIVATE_IPS");
        if (strv_length(info->ipv4_private_ips) > 0)
                fputstrv(f, info->ipv4_private_ips, NULL, &space);

        fputc('\n', f);
        fprintf(f, "%s=", "AZURE_IPV4_PUBLIC_IPS");
        if (strv_length(info->ipv4_public_ips) > 0)
                fputstrv(f, info->ipv4_public_ips, NULL, &space);

        fputc('\n', f);
        fprintf(f, "%s=", "AZURE_IPV4_SUBNET");
        if (in_addr_is_null(AF_INET, &info->subnet) == 0) {
                _cleanup_free_ char *subnet = NULL;

                r = in_addr_to_string(AF_INET, &info->subnet, &subnet);
                if (r >= 0)
                        fputs_with_space(f, subnet, NULL, &space);
        }

        fputc('\n', f);
        fprintf(f, "%s=", "AZURE_IPV4_PREFIXLEN");
        if (info->prefixlen > 0) {
                char s[DECIMAL_STR_MAX(unsigned)];

                xsprintf(s, "%u", info->prefixlen);
                fputs_with_space(f, s, NULL, &space);
        }

        return 0;
}
