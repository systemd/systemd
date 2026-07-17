/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-doh.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "hexdecoct.h"
#include "in-addr-util.h"
#include "log.h"
#include "parse-util.h"
#include "string-util.h"
#include "utf8.h"

#if HAVE_LIBCURL_HEADER && HAVE_LIBCURL_URL

bool dns_over_https_content_type_is_valid(const char *value) {
        return value && strcasecmp(value, DNS_OVER_HTTPS_MEDIA_TYPE) == 0;
}

/* RFC 9111 §5.1 defines Age as delta-seconds, whose numeric format and overflow handling are defined by RFC 9110 §1.2.2:
 * https://datatracker.ietf.org/doc/html/rfc9111#section-5.1
 * https://datatracker.ietf.org/doc/html/rfc9110#section-1.2.2 */
bool dns_over_https_age_parse(const char *value, uint64_t *ret_age) {
        const char *p, *end;
        uint64_t age = 0;

        if (!value)
                return false;

        p = value;
        while (IN_SET(*p, ' ', '\t'))
                p++;

        end = strchrnul(p, ',');
        while (end > p && IN_SET(end[-1], ' ', '\t'))
                end--;
        if (p == end)
                return false;

        for (const char *q = p; q < end; q++) {
                unsigned digit;

                if (!ascii_isdigit(*q))
                        return false;

                digit = *q - '0';
                if (age > (UINT64_MAX - digit) / 10)
                        age = UINT64_MAX;
                else
                        age = age * 10 + digit;
        }

        if (ret_age)
                *ret_age = age;
        return true;
}

int dns_over_https_response_headers_read(CURL *easy, uint64_t *ret_age) {
        struct curl_header *header;
        CURLHcode code;
        uint64_t age = 0;

        assert(easy);

        code = sym_curl_easy_header(easy, "Content-Type", 0, CURLH_HEADER, -1, &header);
        if (code != CURLHE_OK || header->amount != 1 || !dns_over_https_content_type_is_valid(header->value))
                return -EBADMSG;

        code = sym_curl_easy_header(easy, "Age", 0, CURLH_HEADER, -1, &header);
        if (code == CURLHE_OK)
                (void) dns_over_https_age_parse(header->value, &age);
        else if (code != CURLHE_MISSING)
                return code == CURLHE_OUT_OF_MEMORY ? -ENOMEM : -EIO;

        if (ret_age)
                *ret_age = age;
        return 0;
}

/* RFC 8484 §3 defines method-specific URI-template expansion, and §4.1 defines the GET and POST requests:
 * https://datatracker.ietf.org/doc/html/rfc8484#section-3
 * https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
 * GET's unpadded base64url encoding is defined by RFC 4648 §5:
 * https://datatracker.ietf.org/doc/html/rfc4648#section-5 */
int dns_over_https_uri_expand_for_method(const char *uri_template, DnsOverHttpsMethod method, const void *dns_message, size_t dns_message_size, char **ret) {
        _cleanup_free_ char *dns = NULL, *prefix = NULL, *uri = NULL;
        const char *expression;
        ssize_t n;

        assert(uri_template);
        assert(ret);

        if (!IN_SET(method, DNS_OVER_HTTPS_METHOD_POST, DNS_OVER_HTTPS_METHOD_GET) || (!dns_message && dns_message_size > 0))
                return -EINVAL;

        if (method == DNS_OVER_HTTPS_METHOD_GET) {
                n = base64urlmem(dns_message, dns_message_size, &dns);
                if (n < 0)
                        return (int) n;
        }

        expression = strchr(uri_template, '{');
        if (!expression) {
                if (strchr(uri_template, '}'))
                        return -EINVAL;
                if (method == DNS_OVER_HTTPS_METHOD_GET)
                        return -EINVAL;

                uri = strdup(uri_template);
        } else {
                const char *suffix;

                if (!startswith(expression, "{?dns}"))
                        return -EOPNOTSUPP;
                if (memchr(uri_template, '}', expression - uri_template))
                        return -EINVAL;

                suffix = expression + strlen("{?dns}");
                if (strchr(suffix, '{') || strchr(suffix, '}'))
                        return -EOPNOTSUPP;

                prefix = strndup(uri_template, expression - uri_template);
                if (!prefix)
                        return -ENOMEM;

                uri = method == DNS_OVER_HTTPS_METHOD_POST ? strjoin(prefix, suffix) : strjoin(prefix, "?dns=", dns, suffix);
        }
        if (!uri)
                return -ENOMEM;

        *ret = TAKE_PTR(uri);
        return 0;
}

int dns_over_https_uri_parse(const char *uri_template, char **ret_uri, char **ret_auth_name, uint16_t *ret_port) {
        _cleanup_(curl_freep) char *auth_name = NULL, *normalized = NULL, *port_string = NULL, *scheme = NULL;
        _cleanup_(curl_url_cleanupp) CURLU *url = NULL;
        _cleanup_free_ char *expanded = NULL;
        const char *scheme_separator;
        uint16_t port;
        int r;

        assert(uri_template);

        if (!ascii_is_valid(uri_template) || string_has_cc(uri_template, NULL))
                return -EINVAL;

        r = dns_over_https_uri_expand_for_method(uri_template, DNS_OVER_HTTPS_METHOD_POST, NULL, 0, &expanded);
        if (r < 0)
                return r;
        if (strchr(expanded, '#'))
                return -EINVAL;

        /* curl deliberately accepts some non-RFC forms such as https:///path and interprets the first path
         * component as the host. Require an absolute URI with a non-empty authority before handing it to curl. */
        scheme_separator = strchr(expanded, ':');
        if (!scheme_separator || !startswith(scheme_separator, "://") || IN_SET(scheme_separator[3], 0, '/', '?', '#'))
                return -EINVAL;

        r = DLOPEN_CURL(LOG_DEBUG, recommended);
        if (r < 0)
                return r;

        url = sym_curl_url();
        if (!url)
                return -ENOMEM;

        if (sym_curl_url_set(url, CURLUPART_URL, expanded, CURLU_DISALLOW_USER) != CURLUE_OK)
                return -EINVAL;
        if (sym_curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK)
                return -EINVAL;
        if (!streq(scheme, "https"))
                return -EPROTONOSUPPORT;
        if (sym_curl_url_get(url, CURLUPART_HOST, &auth_name, 0) != CURLUE_OK)
                return -EINVAL;

        /* curl returns IPv6 hosts in brackets and keeps any zone ID separately. Strip the URI brackets from the
         * authentication identity; the normalized URI below retains the zone ID used for the connection. */
        if (startswith(auth_name, "[")) {
                _cleanup_free_ char *address = NULL;
                size_t n = strlen(auth_name);

                if (n < 2 || auth_name[n - 1] != ']')
                        return -EINVAL;

                address = strndup(auth_name + 1, n - 2);
                if (!address)
                        return -ENOMEM;
                if (in_addr_from_string(AF_INET6, address, NULL) < 0)
                        return -EINVAL;

                free_and_replace(auth_name, address);
        } else if (dns_name_is_valid_or_address(auth_name) <= 0)
                return -EINVAL;

        if (sym_curl_url_get(url, CURLUPART_PORT, &port_string, CURLU_DEFAULT_PORT) != CURLUE_OK)
                return -EINVAL;
        r = parse_ip_port(port_string, &port);
        if (r < 0)
                return r;

        if (sym_curl_url_get(url, CURLUPART_URL, &normalized, 0) != CURLUE_OK)
                return -EINVAL;

        if (ret_uri)
                *ret_uri = TAKE_PTR(normalized);
        if (ret_auth_name)
                *ret_auth_name = TAKE_PTR(auth_name);
        if (ret_port)
                *ret_port = port;

        return 0;
}

#endif
