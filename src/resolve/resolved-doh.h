/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "curl-util.h"

#if HAVE_LIBCURL_HEADER && HAVE_LIBCURL_URL

#define DNS_OVER_HTTPS_MEDIA_TYPE "application/dns-message"

typedef enum DnsOverHttpsMethod {
        DNS_OVER_HTTPS_METHOD_POST,
        DNS_OVER_HTTPS_METHOD_GET,
        _DNS_OVER_HTTPS_METHOD_MAX,
        _DNS_OVER_HTTPS_METHOD_INVALID = -EINVAL,
} DnsOverHttpsMethod;

bool dns_over_https_content_type_is_valid(const char *value);
bool dns_over_https_age_parse(const char *value, uint64_t *ret_age);

int dns_over_https_response_headers_read(CURL *easy, uint64_t *ret_age);

int dns_over_https_uri_expand_for_method(const char *uri_template, DnsOverHttpsMethod method, const void *dns_message, size_t dns_message_size, char **ret);
int dns_over_https_uri_parse(const char *uri_template, char **ret_uri, char **ret_auth_name, uint16_t *ret_port);

#endif
