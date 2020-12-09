/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if HAVE_LIBCURL
#include <curl/curl.h>
#endif

#include "alloc-util.h"
#include "ether-addr-util.h"
#include "network-cloud-azure.h"
#include "network-cloud-util.h"
#include "parse-util.h"
#include "virt.h"

static int azure_parse_ip_address(JsonVariant *v, AzureCloudMetadata *az) {
        JsonVariant *e;
        int r;

        assert(v);

        JSON_VARIANT_ARRAY_FOREACH(e, v) {
                JsonVariant *w;

                w = json_variant_by_key(e, "privateIpAddress");
                if (w) {
                        r = in_addr_from_string(AF_INET, json_variant_string(w), &az->private_ip);
                        if (r < 0)
                                return r;
                }

                w = json_variant_by_key(e, "publicIpAddress");
                if (w) {
                        r = in_addr_from_string(AF_INET, json_variant_string(w), &az->public_ip);
                        if (r < 0)
                                return 0;
                }
        }

        return 0;
}

static int azure_parse_ip_subnet(JsonVariant *v, AzureCloudMetadata *az) {
        JsonVariant *e;
        int r;

        assert(v);

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

                if (in4_addr_is_null(&az->public_ip.in) != 0 || in4_addr_is_null(&az->private_ip.in) != 0)
                        continue;

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
                        _cleanup_free_ char *s = NULL;

                        (void) format_cloud_to_ether(json_variant_string(d), &s);

                        r = ether_addr_from_string(s, &c->mac);
                        if (r < 0)
                                return r;
                }

                d = json_variant_by_key(e, "ipv4");
                if (d)
                        return azure_parse_ip_subnet_object(d, c);
        }

        return 0;
}

int azure_parse_json_object(NetworkCloudManager *m, JsonVariant *j) {
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

int azure_acquire_cloud_metadata_from_imds(bool perform,  NetworkCloudManager **ret) {
#if HAVE_LIBCURL
        _cleanup_(curl_slist_free_allp) struct curl_slist *request_header = NULL;
        _cleanup_(network_cloud_manager_freep) NetworkCloudManager *m = NULL;
        _cleanup_(curl_easy_cleanupp) CURL *curl = NULL;
        _cleanup_free_ char *url = NULL;
        int r;

        if (detect_virtualization() != VIRTUALIZATION_MICROSOFT)
                return -ENOTSUP;

        r = network_cloud_manager_new(CLOUD_PROVIDER_AZURE, &m);
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

        if (perform) {
                if (curl_easy_perform(curl) != CURLE_OK)
                        return -EIO;
        }

        *ret = TAKE_PTR(m);
        return 0;
#else
        return -ENOTSUP;
#endif
}
