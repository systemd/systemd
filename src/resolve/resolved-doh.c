/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "resolved-doh.h"

#include "alloc-util.h"
#include "dns-domain.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "hexdecoct.h"
#include "in-addr-util.h"
#include "log.h"
#include "parse-util.h"
#include "resolved-dns-delegate.h"
#include "resolved-dns-server.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-transaction.h"
#include "resolved-manager.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"
#include "utf8.h"

#if HAVE_LIBCURL_HEADER && HAVE_LIBCURL_URL

/* RFC 9110 §4.1 recommends that senders and recipients support URIs of at least 8000 octets:
 * https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1 */
#define DNS_OVER_HTTPS_GET_URI_MAX 8000U

struct DnsHttpRequest {
        DnsTransaction *transaction;
        DnsPacket *packet;

        CurlSlot *slot;
        struct curl_slist *headers;
        struct curl_slist *resolve;
        struct curl_slist *connect_to;

        uint8_t *response;
        size_t response_size;
        int response_error;
};

/* RFC 9110 §8.3.1 defines media types as a type/subtype followed by optional parameters:
 * https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1 */
bool dns_over_https_content_type_is_valid(const char *value) {
        const char *p;
        size_t n;

        if (!value)
                return false;

        p = value + strspn(value, " \t");
        n = strcspn(p, ";");
        while (n > 0 && IN_SET(p[n - 1], ' ', '\t'))
                n--;

        return n == STRLEN(DNS_OVER_HTTPS_MEDIA_TYPE) && strncaseeq(p, DNS_OVER_HTTPS_MEDIA_TYPE, n);
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
        if (code == CURLHE_OUT_OF_MEMORY)
                return -ENOMEM;
<<<<<<< HEAD
        if (code != CURLHE_OK || !dns_over_https_content_type_is_valid(header->value))
=======
        if (code != CURLHE_OK || !dns_over_https_content_type_is_valid(header->value))
>>>>>>> 84af685de0 (resolved: improve error handling and retry some failures)
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

DnsOverHttpsFailureAction dns_over_https_curl_failure_action(CURLcode code) {
        switch (code) {
        case CURLE_OK:
        case CURLE_UNSUPPORTED_PROTOCOL:
        case CURLE_FAILED_INIT:
        case CURLE_URL_MALFORMAT:
        case CURLE_NOT_BUILT_IN:
        case CURLE_COULDNT_RESOLVE_PROXY: /* Proxies are disabled for DoH. */
        case CURLE_WRITE_ERROR:           /* Our write callback records its own error first. */
        case CURLE_READ_ERROR:
        case CURLE_OUT_OF_MEMORY:
        case CURLE_ABORTED_BY_CALLBACK:
        case CURLE_BAD_FUNCTION_ARGUMENT:
        case CURLE_INTERFACE_FAILED:
        case CURLE_UNKNOWN_OPTION:
        case CURLE_SETOPT_OPTION_SYNTAX:
        case CURLE_SSL_ENGINE_NOTFOUND:
        case CURLE_SSL_ENGINE_SETFAILED:
        case CURLE_SSL_CERTPROBLEM:
        case CURLE_SSL_CIPHER:
        case CURLE_SEND_FAIL_REWIND:
        case CURLE_SSL_ENGINE_INITFAILED:
        case CURLE_SSL_CACERT_BADFILE:
        case CURLE_AGAIN:                 /* Only returned by curl_easy_send() and curl_easy_recv(). */
        case CURLE_SSL_CRL_BADFILE:
        case CURLE_NO_CONNECTION_AVAILABLE:
        case CURLE_RECURSIVE_API_CALL:
        case CURLE_PROXY:                 /* Proxies are disabled for DoH. */
        case CURLE_UNRECOVERABLE_POLL:
                return DNS_OVER_HTTPS_FAILURE_ABORT;

        case CURLE_COULDNT_CONNECT:
        case CURLE_HTTP2:
        case CURLE_PARTIAL_FILE:
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_GOT_NOTHING:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
        case CURLE_SSL_SHUTDOWN_FAILED:
        case CURLE_HTTP2_STREAM:
        case CURLE_HTTP3:
        case CURLE_QUIC_CONNECT_ERROR:
                return DNS_OVER_HTTPS_FAILURE_RETRY_SAME_SERVER;

        default:
                /* Certificate verification, endpoint incompatibility, and malformed remote data will not be
                 * repaired by opening another connection to the same endpoint. */
                return DNS_OVER_HTTPS_FAILURE_RETRY_NEXT_SERVER;
        }
}

/* RFC 8484 §4.2.1 requires DoH clients to apply normal HTTP semantics to non-successful responses:
 * https://www.rfc-editor.org/rfc/rfc8484.html#section-4.2.1 */
DnsOverHttpsFailureAction dns_over_https_http_failure_action(long status) {
        if (status >= 200 && status < 300)
                return DNS_OVER_HTTPS_FAILURE_ABORT;

        if (IN_SET(status, 408L, 421L, 425L, 502L, 504L))
                return DNS_OVER_HTTPS_FAILURE_RETRY_SAME_SERVER;

        /* In particular, rotate immediately for 429 and 503 because delayed Retry-After scheduling is not
         * implemented. Opening a fresh connection would not repair other endpoint or application failures. */
        if (status > 0)
                return DNS_OVER_HTTPS_FAILURE_RETRY_NEXT_SERVER;

        return DNS_OVER_HTTPS_FAILURE_ABORT;
}

static const char* const dns_over_https_failure_action_table[_DNS_OVER_HTTPS_FAILURE_ACTION_MAX] = {
        [DNS_OVER_HTTPS_FAILURE_ABORT]             = "abort",
        [DNS_OVER_HTTPS_FAILURE_RETRY_SAME_SERVER] = "retry-same-server",
        [DNS_OVER_HTTPS_FAILURE_RETRY_NEXT_SERVER] = "retry-next-server",
};
DEFINE_STRING_TABLE_LOOKUP(dns_over_https_failure_action, DnsOverHttpsFailureAction);

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

                uri = method == DNS_OVER_HTTPS_METHOD_POST ? strjoin(prefix, suffix) : strjoin(prefix, strchr(prefix, '?') ? "&dns=" : "?dns=", dns, suffix);
        }
        if (!uri)
                return -ENOMEM;

        *ret = TAKE_PTR(uri);
        return 0;
}

static int dns_over_https_uri_template_normalize(const char *uri_template, const char *normalized_uri, char **ret) {
        const char *normalized_authority, *normalized_tail, *template_authority, *template_tail;
        _cleanup_free_ char *prefix = NULL, *result = NULL;

        assert(uri_template);
        assert(normalized_uri);
        assert(ret);

        normalized_authority = ASSERT_PTR(strstr(normalized_uri, "://")) + 3;
        normalized_tail = ASSERT_PTR(strchr(normalized_authority, '/'));
        template_authority = ASSERT_PTR(strstr(uri_template, "://")) + 3;
        template_tail = strpbrk(template_authority, "/?{");

        if (!template_tail) {
                result = strdup(normalized_uri);
                if (!result)
                        return -ENOMEM;
        } else {
                prefix = strndup(normalized_uri, normalized_tail - normalized_uri);
                if (!prefix)
                        return -ENOMEM;

                result = template_tail[0] == '/' ? strjoin(prefix, template_tail) : strjoin(prefix, "/", template_tail);
                if (!result)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(result);
        return 0;
}

int dns_over_https_uri_parse(const char *uri_template, char **ret_uri, char **ret_uri_template, char **ret_auth_name, uint16_t *ret_port) {
        _cleanup_(curl_freep) char *curl_auth_name = NULL, *normalized = NULL, *port_string = NULL, *scheme = NULL;
        _cleanup_(curl_url_cleanupp) CURLU *url = NULL;
        _cleanup_free_ char *auth_name = NULL, *expanded = NULL, *normalized_template = NULL;
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
        if (sym_curl_url_get(url, CURLUPART_HOST, &curl_auth_name, 0) != CURLUE_OK)
                return -EINVAL;

        auth_name = strdup(curl_auth_name);
        if (!auth_name)
                return -ENOMEM;

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

        r = dns_over_https_uri_template_normalize(uri_template, normalized, &normalized_template);
        if (r < 0)
                return r;

        if (ret_uri)
                *ret_uri = TAKE_PTR(normalized);
        if (ret_uri_template)
                *ret_uri_template = TAKE_PTR(normalized_template);
        if (ret_auth_name)
                *ret_auth_name = TAKE_PTR(auth_name);
        if (ret_port)
                *ret_port = port;

        return 0;
}

static int dns_over_https_bootstrap_address(const DnsServer *server, char **ret) {
        _cleanup_free_ char *address = NULL;
        int r;

        assert(server);
        assert(ret);

        r = in_addr_to_string(server->family, &server->address, &address);
        if (r < 0)
                return r;

        if (server->family == AF_INET6) {
                char *wrapped = strjoin("[", address, "]");
                if (!wrapped)
                        return -ENOMEM;

                free_and_replace(address, wrapped);
        }

        *ret = TAKE_PTR(address);
        return 0;
}

static int dns_over_https_make_resolve_entry(const DnsServer *server, bool auth_name_is_ipv6, char **ret) {
        _cleanup_free_ char *address = NULL, *auth_name = NULL;
        int r;

        assert(server);
        assert(server->server_name);
        assert(ret);

        r = dns_over_https_bootstrap_address(server, &address);
        if (r < 0)
                return r;

        if (auth_name_is_ipv6) {
                auth_name = strjoin("[", server->server_name, "]");
                if (!auth_name)
                        return -ENOMEM;
        }

        if (asprintf(ret, "%s:%" PRIu16 ":%s", auth_name ?: server->server_name, dns_server_port(server), address) < 0)
                return -ENOMEM;

        return 0;
}

static int dns_over_https_make_connect_to_entry(const DnsServer *server, char **ret) {
        _cleanup_free_ char *address = NULL;
        int r;

        assert(server);
        assert(server->server_name);
        assert(ret);

        r = dns_over_https_bootstrap_address(server, &address);
        if (r < 0)
                return r;

        /* CURLOPT_RESOLVE did not support an IPv6 literal as its HOST component until libcurl 8.13.0. An
         * empty HOST in CURLOPT_CONNECT_TO safely matches this request while retaining the URI authority for
         * TLS identity and certificate verification. Redirects are disabled, so the wildcard cannot affect another origin. */
        if (asprintf(ret, ":%" PRIu16 ":%s:%" PRIu16, dns_server_port(server), address, dns_server_port(server)) < 0)
                return -ENOMEM;

        return 0;
}

int dns_over_https_make_connection_override(const DnsServer *server, unsigned curl_version, bool *ret_use_resolve, char **ret) {
        bool auth_name_is_ipv6;
        int r;

        assert(server);
        assert(server->server_name);
        assert(ret_use_resolve);
        assert(ret);

        auth_name_is_ipv6 = in_addr_from_string(AF_INET6, server->server_name, NULL) >= 0;
        if (auth_name_is_ipv6 && curl_version < CURL_VERSION_BITS(8, 13, 0)) {
                r = dns_over_https_make_connect_to_entry(server, ret);
                if (r < 0)
                        return r;

                *ret_use_resolve = false;
        } else {
                r = dns_over_https_make_resolve_entry(server, auth_name_is_ipv6, ret);
                if (r < 0)
                        return r;

                *ret_use_resolve = true;
        }

        return 0;
}

DnsHttpRequest* dns_http_request_free(DnsHttpRequest *request) {
        if (!request)
                return NULL;

        request->slot = curl_slot_unref(request->slot);
        if (request->headers)
                sym_curl_slist_free_all(request->headers);
        if (request->resolve)
                sym_curl_slist_free_all(request->resolve);
        if (request->connect_to)
                sym_curl_slist_free_all(request->connect_to);
        free(request->response);
        dns_packet_unref(request->packet);
        return mfree(request);
}

static size_t dns_http_request_write(const void *contents, size_t size, size_t nmemb, void *userdata) {
        DnsHttpRequest *request = ASSERT_PTR(userdata);
        size_t add;

        if (nmemb > 0 && size > SIZE_MAX / nmemb) {
                request->response_error = -EOVERFLOW;
                return 0;
        }

        add = size * nmemb;
        if (add == 0)
                return 0;
        if (add > DNS_PACKET_SIZE_MAX - request->response_size) {
                request->response_error = -EFBIG;
                return 0;
        }

        if (!GREEDY_REALLOC(request->response, request->response_size + add)) {
                request->response_error = -ENOMEM;
                return 0;
        }

        memcpy(request->response + request->response_size, contents, add);
        request->response_size += add;
        return add;
}

static int dns_http_request_set_socket_options(void *userdata, curl_socket_t fd, curlsocktype purpose) {
        DnsHttpRequest *request = ASSERT_PTR(userdata);
        DnsTransaction *transaction = ASSERT_PTR(request->transaction);
        DnsServer *server = ASSERT_PTR(transaction->server);
        int r;

        assert(transaction->scope);
        assert(fd >= 0);

        if (purpose != CURLSOCKTYPE_IPCXN)
                return CURL_SOCKOPT_OK;

        if (dns_server_ifindex(server) > 0) {
                r = socket_set_unicast_if(fd, server->family, dns_server_ifindex(server));
                if (r < 0) {
                        log_debug_errno(r, "Failed to bind DNS-over-HTTPS socket to interface: %m");
                        return CURL_SOCKOPT_ERROR;
                }
        }

        if (transaction->scope->delegate && transaction->scope->delegate->fwmark > 0) {
                r = setsockopt_int(fd, SOL_SOCKET, SO_MARK, transaction->scope->delegate->fwmark);
                if (r < 0) {
                        log_debug_errno(r, "Failed to set firewall mark on DNS-over-HTTPS socket: %m");
                        return CURL_SOCKOPT_ERROR;
                }
        }

        return CURL_SOCKOPT_OK;
}

static int dns_http_request_make_packet(DnsHttpRequest *request, DnsServer *server, uint64_t age, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        int r;

        assert(request);
        assert(server);
        assert(ret);

        if (request->response_size < DNS_PACKET_HEADER_SIZE)
                return -EBADMSG;

        r = dns_packet_new(&packet, DNS_PROTOCOL_DNS, request->response_size, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        memcpy(DNS_PACKET_DATA(packet), request->response, request->response_size);
        packet->size = request->response_size;
        packet->timestamp = now(CLOCK_BOOTTIME);
        packet->family = server->family;
        packet->sender = server->address;
        packet->sender_port = dns_server_port(server);
        packet->ifindex = dns_server_ifindex(server);

        r = dns_packet_validate_reply(packet);
        if (r <= 0)
                return r < 0 ? r : -EBADMSG;
        if (DNS_PACKET_ID(packet) != 0 || DNS_PACKET_TC(packet))
                return -EBADMSG;

        r = dns_packet_patch_ttls_by_age(packet, age);
        if (r < 0)
                return r;

        r = dns_packet_extract(request->packet);
        if (r < 0)
                return r;
        r = dns_packet_extract(packet);
        if (r < 0)
                return r;

        r = dns_question_is_equal(request->packet->question, packet->question);
        if (r <= 0)
                return r < 0 ? r : -EBADMSG;

        *ret = TAKE_PTR(packet);
        return 0;
}

static int dns_http_request_finished(CurlSlot *slot, CURL *easy, CURLcode code, void *userdata) {
        _cleanup_(dns_http_request_freep) DnsHttpRequest *request = ASSERT_PTR(userdata);
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        DnsServer *server = ASSERT_PTR(request->transaction->server);
        DnsOverHttpsFailureAction failure_action = DNS_OVER_HTTPS_FAILURE_ABORT;
        uint64_t age = 0;
        long status = 0;
        int r;

        assert(slot);
        assert(easy);

        if (request->response_error < 0) {
                r = request->response_error;
                failure_action = r == -ENOMEM ? DNS_OVER_HTTPS_FAILURE_ABORT : DNS_OVER_HTTPS_FAILURE_RETRY_NEXT_SERVER;
        } else if (code != CURLE_OK) {
                log_debug("DNS-over-HTTPS request to %s at %s failed with libcurl error %u (%s).", server->server_name, dns_server_string(server), code, sym_curl_easy_strerror(code));
                failure_action = dns_over_https_curl_failure_action(code);
                r = code == CURLE_OPERATION_TIMEDOUT ? -ETIMEDOUT : -EIO;
        } else if (sym_curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) {
                r = -EIO;
                failure_action = DNS_OVER_HTTPS_FAILURE_ABORT;
        } else if (status < 200 || status >= 300) {
                log_debug("DNS-over-HTTPS request to %s at %s returned HTTP status %ld.", server->server_name, dns_server_string(server), status);
                failure_action = dns_over_https_http_failure_action(status);
                r = -EREMOTEIO;
        } else {
                r = dns_over_https_response_headers_read(easy, &age);
                if (r < 0)
                        failure_action = IN_SET(r, -ENOMEM, -EIO) ? DNS_OVER_HTTPS_FAILURE_ABORT : DNS_OVER_HTTPS_FAILURE_RETRY_NEXT_SERVER;
                else {
                        r = dns_http_request_make_packet(request, server, age, &packet);
                        if (r < 0)
                                failure_action = r == -ENOMEM ? DNS_OVER_HTTPS_FAILURE_ABORT : DNS_OVER_HTTPS_FAILURE_RETRY_NEXT_SERVER;
                }
        }

        if (r < 0)
                log_debug("DNS-over-HTTPS failure action for %s at %s: %s.", server->server_name, dns_server_string(server), dns_over_https_failure_action_to_string(failure_action));

        dns_transaction_on_doh_complete(request->transaction, request, packet, r, failure_action);
        return 0;
}

static int dns_http_request_set_options(CURL *easy, DnsHttpRequest *request, DnsOverHttpsMethod method, bool fresh_connection) {
        DnsServer *server;

        assert(easy);
        assert(request);
        assert(request->transaction);

        server = ASSERT_PTR(request->transaction->server);

        /* A DoH transfer is a DNS protocol exchange with a preconfigured endpoint, not a general-purpose web request.
         * Keep the configured authority fixed, exclude ambient proxy/authentication/cookie state, restrict transfers to
         * HTTPS, prefer HTTP/2, and retain control of socket routing. See RFC 8484 §§3–5. */
        if (!easy_setopt(easy, LOG_DEBUG, CURLOPT_HTTPHEADER, request->headers) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_WRITEFUNCTION, dns_http_request_write) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_WRITEDATA, request) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_SOCKOPTFUNCTION, dns_http_request_set_socket_options) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_SOCKOPTDATA, request) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_FOLLOWLOCATION, 0L) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_MAXREDIRS, 0L) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_VERBOSE, 0L) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_HTTP_VERSION, (long) CURL_HTTP_VERSION_2TLS) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_PROXY, "") ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_HTTPAUTH, (long) CURLAUTH_NONE) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_PROXYAUTH, (long) CURLAUTH_NONE) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_NETRC, (long) CURL_NETRC_IGNORED) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_UNRESTRICTED_AUTH, 0L) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_USERAGENT, (char*) NULL) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_COOKIEFILE, (char*) NULL))
                return -EIO;

        if (method == DNS_OVER_HTTPS_METHOD_GET) {
                if (!easy_setopt(easy, LOG_DEBUG, CURLOPT_HTTPGET, 1L))
                        return -EIO;
        } else if (!easy_setopt(easy, LOG_DEBUG, CURLOPT_POST, 1L) ||
                   !easy_setopt(easy, LOG_DEBUG, CURLOPT_POSTFIELDS, DNS_PACKET_DATA(request->packet)) ||
                   !easy_setopt(easy, LOG_DEBUG, CURLOPT_POSTFIELDSIZE, (long) request->packet->size))
                return -EIO;

        if (request->resolve && !easy_setopt(easy, LOG_DEBUG, CURLOPT_RESOLVE, request->resolve))
                return -EIO;
        if (request->connect_to && !easy_setopt(easy, LOG_DEBUG, CURLOPT_CONNECT_TO, request->connect_to))
                return -EIO;
        if (server->family == AF_INET6 && dns_server_ifindex(server) > 0 &&
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_ADDRESS_SCOPE, (long) dns_server_ifindex(server)))
                return -EIO;

#if LIBCURL_VERSION_NUM >= 0x075500 /* libcurl 7.85.0 */
        if (!easy_setopt(easy, LOG_DEBUG, CURLOPT_PROTOCOLS_STR, "HTTPS") ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_REDIR_PROTOCOLS_STR, "HTTPS"))
                return -EIO;
#else
        if (!easy_setopt(easy, LOG_DEBUG, CURLOPT_PROTOCOLS, (long) CURLPROTO_HTTPS) ||
            !easy_setopt(easy, LOG_DEBUG, CURLOPT_REDIR_PROTOCOLS, (long) CURLPROTO_HTTPS))
                return -EIO;
#endif

        /* Retry one transient failure without reusing the connection that might have caused it. */
        if (fresh_connection && !easy_setopt(easy, LOG_DEBUG, CURLOPT_FRESH_CONNECT, 1L))
                return -EIO;

        return 0;
}

int dns_over_https_uri_for_request(const char *uri_template, const char *post_uri, const void *dns_message, size_t dns_message_size, DnsOverHttpsMethod *ret_method, char **ret_uri) {
        _cleanup_free_ char *uri = NULL;
        DnsOverHttpsMethod method;
        int r;

        assert(uri_template);
        assert(post_uri);
        assert(dns_message || dns_message_size == 0);
        assert(ret_method);
        assert(ret_uri);

        method = DNS_OVER_HTTPS_METHOD_GET;
        r = dns_over_https_uri_expand_for_method(uri_template, method, dns_message, dns_message_size, &uri);
        if (r == -EINVAL || (r >= 0 && strlen(uri) > DNS_OVER_HTTPS_GET_URI_MAX)) {
                method = DNS_OVER_HTTPS_METHOD_POST;
                uri = mfree(uri);
                uri = strdup(post_uri);
                if (!uri)
                        return -ENOMEM;
        } else if (r < 0)
                return r;

        *ret_method = method;
        *ret_uri = TAKE_PTR(uri);
        return 0;
}

int dns_http_request_new(DnsTransaction *transaction, DnsServer *server, DnsPacket *packet, bool fresh_connection, DnsHttpRequest **ret) {
        _cleanup_(curl_easy_cleanupp) CURL *easy = NULL;
        _cleanup_(dns_http_request_freep) DnsHttpRequest *request = NULL;
        _cleanup_free_ char *override = NULL, *uri = NULL;
        const curl_version_info_data *curl_version;
        DnsOverHttpsMethod method;
        bool use_resolve;
        int r;

        assert(transaction);
        assert(server);
        assert(dns_server_is_doh(server));
        assert(server->doh_uri);
        assert(server->server_name);
        assert(packet);
        assert(ret);

        if (!server->doh_curl) {
                r = curl_glue_new(&server->doh_curl, server->manager->event);
                if (r < 0)
                        return r;
        }

        request = new0(DnsHttpRequest, 1);
        if (!request)
                return -ENOMEM;

        request->transaction = transaction;

        r = dns_packet_dup(&request->packet, packet);
        if (r < 0)
                return r;
        DNS_PACKET_HEADER(request->packet)->id = 0;

        r = dns_over_https_uri_for_request(server->doh_uri_template, server->doh_uri, DNS_PACKET_DATA(request->packet), request->packet->size, &method, &uri);
        if (r < 0)
                return r;

        request->headers = method == DNS_OVER_HTTPS_METHOD_GET ? curl_slist_new("Accept: " DNS_OVER_HTTPS_MEDIA_TYPE, NULL) : curl_slist_new("Content-Type: " DNS_OVER_HTTPS_MEDIA_TYPE, "Accept: " DNS_OVER_HTTPS_MEDIA_TYPE, NULL);
        if (!request->headers)
                return -ENOMEM;

        curl_version = sym_curl_version_info(CURLVERSION_FIRST);
        if (!curl_version)
                return -EIO;

        r = dns_over_https_make_connection_override(server, curl_version->version_num, &use_resolve, &override);
        if (r < 0)
                return r;

        if (use_resolve) {
                request->resolve = sym_curl_slist_append(NULL, override);
                if (!request->resolve)
                        return -ENOMEM;
        } else {
                request->connect_to = sym_curl_slist_append(NULL, override);
                if (!request->connect_to)
                        return -ENOMEM;
        }

        r = curl_glue_make(&easy, uri);
        if (r < 0)
                return r;

        r = dns_http_request_set_options(easy, request, method, fresh_connection);
        if (r < 0)
                return r;

        log_debug("Sending DNS-over-HTTPS %s to %s at bootstrap address %s.", method == DNS_OVER_HTTPS_METHOD_GET ? "GET" : "POST", server->server_name, dns_server_string(server));

        r = curl_glue_perform_async(server->doh_curl, easy, dns_http_request_finished, request, &request->slot);
        if (r < 0)
                return r;
        TAKE_PTR(easy);

        *ret = TAKE_PTR(request);
        return 0;
}

#endif
