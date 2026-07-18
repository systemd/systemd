/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <glib-unix.h>
#include <libsoup/soup.h>
#include <sys/socket.h>

#undef ABS

#include "sd-daemon.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "dns-answer.h"
#include "dns-packet.h"
#include "dns-question.h"
#include "dns-rr.h"
#include "dns-type.h"
#include "errno-util.h"
#include "hexdecoct.h"
#include "in-addr-util.h"
#include "log.h"
#include "main-func.h"
#include "parse-util.h"
#include "string-util.h"

#define DNS_TEST_TTL 300U
#define REQUEST_HISTORY_MAX 128U

typedef struct RequestObservation {
        char *path;
        char *method;
        char *http_version;
        char *accept;
        char *content_type;
        char *question;
        uint64_t request_id;
        uint64_t connection_id;
        uint64_t body_size;
        uint16_t dns_id;
        unsigned response_status;
        int response_dns_rcode;
        bool have_dns_id;
        bool has_opt;
        bool do_bit;
} RequestObservation;

typedef struct ActiveRequest {
        char *path;
        uint64_t request_id;
        uint64_t connection_id;
} ActiveRequest;

typedef struct ServerContext {
        SoupServer *server;
        GMainLoop *loop;
        GHashTable *request_counts;
        GHashTable *connections;
        GHashTable *active_messages;
        GHashTable *paused_messages;
        GPtrArray *history;
        uint64_t n_requests;
        uint64_t next_connection_id;
        unsigned n_active;
} ServerContext;

static void uri_list_freep(GSList **uris) {
        if (*uris)
                g_slist_free_full(*uris, (GDestroyNotify) g_uri_unref);
}

static void request_observation_free(gpointer p) {
        RequestObservation *o = p;

        if (!o)
                return;

        g_free(o->path);
        g_free(o->method);
        g_free(o->http_version);
        g_free(o->accept);
        g_free(o->content_type);
        g_free(o->question);
        g_free(o);
}

static void active_request_free(gpointer p) {
        ActiveRequest *request = p;

        if (!request)
                return;

        g_free(request->path);
        g_free(request);
}

static void server_context_done(ServerContext *c) {
        assert(c);

        g_hash_table_unref(c->paused_messages);
        g_hash_table_unref(c->active_messages);
        g_hash_table_unref(c->connections);
        g_hash_table_unref(c->request_counts);
        g_ptr_array_unref(c->history);
}

static void server_context_init(ServerContext *c) {
        assert(c);

        c->request_counts = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        c->connections = g_hash_table_new_full(g_direct_hash, g_direct_equal, g_object_unref, g_free);
        c->active_messages = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, active_request_free);
        c->paused_messages = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_object_unref);
        c->history = g_ptr_array_new_with_free_func(request_observation_free);
        c->next_connection_id = 1;
}

static const char* http_version_to_string(SoupHTTPVersion version) {
        switch (version) {
        case SOUP_HTTP_1_0:
                return "1.0";
        case SOUP_HTTP_1_1:
                return "1.1";
        case SOUP_HTTP_2_0:
                return "2";
        default:
                return "unknown";
        }
}

static uint64_t connection_id(ServerContext *c, SoupServerMessage *message) {
        GSocket *socket;
        uint64_t *id;

        assert(c);
        assert(message);

        socket = soup_server_message_get_socket(message);
        if (!socket)
                return 0;

        id = g_hash_table_lookup(c->connections, socket);
        if (id)
                return *id;

        id = g_new(uint64_t, 1);
        *id = c->next_connection_id++;
        g_hash_table_insert(c->connections, g_object_ref(socket), id);
        return *id;
}

static uint64_t increment_request_count(ServerContext *c, const char *path) {
        uint64_t *count;

        assert(c);
        assert(path);

        count = g_hash_table_lookup(c->request_counts, path);
        if (!count) {
                count = g_new0(uint64_t, 1);
                g_hash_table_insert(c->request_counts, g_strdup(path), count);
        }

        return ++*count;
}

static RequestObservation* record_request(ServerContext *c, SoupServerMessage *message, const char *path, DnsPacket *packet) {
        RequestObservation *o;
        ActiveRequest *active;
        SoupMessageBody *body;
        SoupMessageHeaders *headers;

        assert(c);
        assert(message);
        assert(path);

        body = soup_server_message_get_request_body(message);
        headers = soup_server_message_get_request_headers(message);

        o = g_new0(RequestObservation, 1);
        o->request_id = ++c->n_requests;
        o->path = g_strdup(path);
        o->method = g_strdup(soup_server_message_get_method(message));
        o->http_version = g_strdup(http_version_to_string(soup_server_message_get_http_version(message)));
        o->accept = g_strdup(soup_message_headers_get_one(headers, "Accept"));
        o->content_type = g_strdup(soup_message_headers_get_one(headers, "Content-Type"));
        o->connection_id = connection_id(c, message);
        o->body_size = body && body->length > 0 ? (uint64_t) body->length : 0;

        if (packet) {
                o->dns_id = be16toh(DNS_PACKET_ID(packet));
                o->have_dns_id = true;
                o->question = g_strdup(dns_question_first_name(packet->question));
                o->has_opt = !!packet->opt;
                o->do_bit = dns_packet_do(packet);
        }

        if (c->history->len >= REQUEST_HISTORY_MAX)
                g_ptr_array_remove_index(c->history, 0);
        g_ptr_array_add(c->history, o);

        c->n_active++;
        active = g_new0(ActiveRequest, 1);
        active->path = g_strdup(path);
        active->request_id = o->request_id;
        active->connection_id = o->connection_id;
        g_hash_table_insert(c->active_messages, message, active);
        (void) increment_request_count(c, path);

        return o;
}

static void request_done(ServerContext *c, SoupServerMessage *message, const char *result) {
        ActiveRequest *request;
        SoupMessageBody *body;
        SoupMessageHeaders *headers;
        unsigned status;

        assert(c);
        assert(message);
        assert(result);

        request = g_hash_table_lookup(c->active_messages, message);
        if (!request)
                return;

        status = soup_server_message_get_status(message);
        body = soup_server_message_get_response_body(message);
        headers = soup_server_message_get_response_headers(message);

        if (status > 0)
                log_info("Request #%" PRIu64 " on connection #%" PRIu64
                         " %s with HTTP status %u and a %" PRIu64 " byte response.",
                         request->request_id, request->connection_id, result, status, body ? (uint64_t) body->length : 0);
        else
                log_info("Request #%" PRIu64 " on connection #%" PRIu64 " %s without an HTTP response.",
                         request->request_id, request->connection_id, result);

        log_debug("Request #%" PRIu64 " response headers: Content-Type=%s, Age=%s",
                  request->request_id,
                  strna(soup_message_headers_get_one(headers, "Content-Type")),
                  strna(soup_message_headers_get_one(headers, "Age")));

        assert(c->n_active > 0);
        c->n_active--;
        g_hash_table_remove(c->active_messages, message);

        (void) g_hash_table_remove(c->paused_messages, message);
}

static void on_request_finished(SoupServer *server, SoupServerMessage *message, gpointer userdata) {
        request_done(userdata, message, "finished");
}

static void on_request_aborted(SoupServer *server, SoupServerMessage *message, gpointer userdata) {
        request_done(userdata, message, "was aborted");
}

static void on_paused_request_finished(SoupServerMessage *message, gpointer userdata) {
        request_done(userdata, message, "finished while paused");
}

static int dns_packet_check_wire_size(DnsPacket *packet) {
        size_t saved_rindex;
        int r = 0;

        assert(packet);

        saved_rindex = packet->rindex;
        dns_packet_rewind(packet, DNS_PACKET_HEADER_SIZE);

        for (unsigned i = 0; i < DNS_PACKET_QDCOUNT(packet); i++) {
                _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;

                r = dns_packet_read_key(packet, &key, NULL, NULL);
                if (r < 0)
                        goto finish;
        }

        for (unsigned i = 0; i < DNS_PACKET_RRCOUNT(packet); i++) {
                _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;

                r = dns_packet_read_rr(packet, &rr, NULL, NULL);
                if (r < 0)
                        goto finish;
        }

        if (packet->rindex != packet->size)
                r = -EBADMSG;

finish:
        dns_packet_rewind(packet, saved_rindex);
        return r;
}

static int dns_packet_from_bytes(const void *data, size_t size, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *packet = NULL;
        int r;

        assert(data || size == 0);
        assert(ret);

        if (size > DNS_PACKET_SIZE_MAX)
                return -EFBIG;

        r = dns_packet_new(&packet, DNS_PROTOCOL_DNS, size, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        if (size > 0)
                memcpy(DNS_PACKET_DATA(packet), data, size);
        packet->size = size;

        r = dns_packet_validate_query(packet);
        if (r <= 0)
                return r < 0 ? r : -EBADMSG;

        r = dns_packet_check_wire_size(packet);
        if (r < 0)
                return r;

        r = dns_packet_extract(packet);
        if (r < 0)
                return r;

        if (dns_question_size(packet->question) != 1 || be16toh(DNS_PACKET_ID(packet)) != 0)
                return -EBADMSG;

        *ret = TAKE_PTR(packet);
        return 0;
}

static bool base64url_is_valid(const char *s) {
        assert(s);

        if (isempty(s))
                return false;

        for (const char *p = s; *p; p++)
                if (!ascii_isalpha(*p) && !ascii_isdigit(*p) && !IN_SET(*p, '-', '_'))
                        return false;

        return true;
}

static int decode_base64url(const char *encoded, void **ret, size_t *ret_size) {
        _cleanup_free_ void *decoded = NULL;
        _cleanup_free_ char *padded = NULL;
        size_t encoded_size, padding;
        int r;

        assert(encoded);
        assert(ret);
        assert(ret_size);

        if (!base64url_is_valid(encoded))
                return -EINVAL;

        encoded_size = strlen(encoded);
        if (encoded_size % 4 == 1)
                return -EINVAL;

        padding = (4 - encoded_size % 4) % 4;
        padded = new(char, encoded_size + padding + 1);
        if (!padded)
                return -ENOMEM;

        memcpy(padded, encoded, encoded_size);
        memset(padded + encoded_size, '=', padding);
        padded[encoded_size + padding] = 0;

        r = unbase64mem(padded, &decoded, ret_size);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(decoded);
        return 0;
}

static int request_dns_packet(SoupServerMessage *message, DnsPacket **ret) {
        _cleanup_free_ void *decoded = NULL;
        SoupMessageBody *body;
        SoupMessageHeaders *headers;
        const char *method, *query;
        size_t decoded_size;
        int r;

        assert(message);
        assert(ret);

        method = soup_server_message_get_method(message);
        headers = soup_server_message_get_request_headers(message);

        if (!streq_ptr(soup_message_headers_get_one(headers, "Accept"), "application/dns-message"))
                return -EINVAL;

        if (streq(method, SOUP_METHOD_GET)) {
                query = g_uri_get_query(soup_server_message_get_uri(message));
                if (!query || !startswith(query, "dns="))
                        return -EINVAL;

                query += STRLEN("dns=");
                r = decode_base64url(query, &decoded, &decoded_size);
                if (r < 0)
                        return r;

                return dns_packet_from_bytes(decoded, decoded_size, ret);
        }

        if (!streq(method, SOUP_METHOD_POST))
                return -EOPNOTSUPP;

        if (!streq_ptr(soup_message_headers_get_one(headers, "Content-Type"), "application/dns-message"))
                return -EINVAL;

        body = soup_server_message_get_request_body(message);
        if (!body || body->length < 0)
                return -EINVAL;

        return dns_packet_from_bytes(body->data, (size_t) body->length, ret);
}

static int make_question(const DnsResourceKey *original, const char *name, DnsQuestion **ret) {
        _cleanup_(dns_resource_key_unrefp) DnsResourceKey *key = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *question = NULL;
        int r;

        assert(original);
        assert(name);
        assert(ret);

        key = dns_resource_key_new(original->class, original->type, name);
        if (!key)
                return -ENOMEM;

        question = dns_question_new(1);
        if (!question)
                return -ENOMEM;

        r = dns_question_add(question, key, 0);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(question);
        return 0;
}

static int make_dns_reply(DnsPacket *query, DnsQuestion *question, int rcode, bool suppress_opt, DnsPacket **ret) {
        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr = NULL;
        union in_addr_union address;
        DnsResourceKey *key;
        int r;

        assert(query);
        assert(ret);

        question = question ?: query->question;
        key = dns_question_first_key(question);

        r = dns_packet_new(&reply, DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX);
        if (r < 0)
                return r;

        r = dns_packet_append_question(reply, question);
        if (r < 0)
                return r;

        DNS_PACKET_HEADER(reply)->id = DNS_PACKET_ID(query);
        DNS_PACKET_HEADER(reply)->flags = htobe16(DNS_PACKET_MAKE_FLAGS(
                                1, 0, 0, 0, DNS_PACKET_RD(query), 1, 0, DNS_PACKET_CD(query), rcode));
        DNS_PACKET_HEADER(reply)->qdcount = htobe16(1);

        if (rcode == DNS_RCODE_SUCCESS && key->class == DNS_CLASS_IN && IN_SET(key->type, DNS_TYPE_A, DNS_TYPE_AAAA)) {
                rr = dns_resource_record_new_full(key->class, key->type, dns_resource_key_name(key));
                if (!rr)
                        return -ENOMEM;

                rr->ttl = DNS_TEST_TTL;
                if (key->type == DNS_TYPE_A)
                        rr->a.in_addr.s_addr = htobe32(UINT32_C(0xc0000201));
                else {
                        r = in_addr_from_string(AF_INET6, "2001:db8::1", &address);
                        if (r < 0)
                                return r;
                        rr->aaaa.in6_addr = address.in6;
                }

                r = dns_packet_append_rr(reply, rr, 0, NULL, NULL);
                if (r < 0)
                        return r;

                DNS_PACKET_HEADER(reply)->ancount = htobe16(1);
        }

        if (query->opt && !suppress_opt) {
                r = dns_packet_append_opt(reply, DNS_PACKET_SIZE_MAX, dns_packet_do(query), false, NULL, rcode, NULL);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(reply);
        return 0;
}

static void set_response_body(SoupServerMessage *message, const void *data, size_t size) {
        SoupMessageBody *body;

        assert(message);
        assert(data || size == 0);

        body = soup_server_message_get_response_body(message);
        soup_message_body_truncate(body);
        soup_message_body_append(body, SOUP_MEMORY_COPY, data, size);
        soup_message_body_complete(body);
}

static void respond_plain(SoupServerMessage *message, unsigned status, const char *text) {
        assert(message);
        assert(text);

        soup_server_message_set_status(message, status, NULL);
        soup_server_message_set_response(message, "text/plain", SOUP_MEMORY_COPY, text, strlen(text));
}

static void respond_dns_packet(
                SoupServerMessage *message,
                DnsPacket *packet,
                const char *content_type,
                const char *age,
                bool duplicate_content_type,
                bool duplicate_age) {

        SoupMessageHeaders *headers;

        assert(message);
        assert(packet);

        soup_server_message_set_status(message, SOUP_STATUS_OK, NULL);
        headers = soup_server_message_get_response_headers(message);

        if (content_type) {
                soup_message_headers_append(headers, "Content-Type", content_type);
                if (duplicate_content_type)
                        soup_message_headers_append(headers, "Content-Type", content_type);
        }

        if (age) {
                soup_message_headers_append(headers, "Age", age);
                if (duplicate_age)
                        soup_message_headers_append(headers, "Age", "61");
        }

        set_response_body(message, DNS_PACKET_DATA(packet), packet->size);
}

static int make_state_json(ServerContext *c, char **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *counts = NULL, *history = NULL, *root = NULL;
        GHashTableIter iterator;
        gpointer key, value;
        int r;

        assert(c);
        assert(ret);

        g_hash_table_iter_init(&iterator, c->request_counts);
        while (g_hash_table_iter_next(&iterator, &key, &value)) {
                r = sd_json_variant_append_arraybo(
                                &counts,
                                SD_JSON_BUILD_PAIR_STRING("path", key),
                                SD_JSON_BUILD_PAIR_UNSIGNED("count", *(uint64_t*) value));
                if (r < 0)
                        return r;
        }

        for (guint i = 0; i < c->history->len; i++) {
                RequestObservation *o = g_ptr_array_index(c->history, i);

                r = sd_json_variant_append_arraybo(
                                &history,
                                SD_JSON_BUILD_PAIR_STRING("path", o->path),
                                SD_JSON_BUILD_PAIR_STRING("method", o->method),
                                SD_JSON_BUILD_PAIR_STRING("httpVersion", o->http_version),
                                SD_JSON_BUILD_PAIR_STRING("accept", o->accept ?: ""),
                                SD_JSON_BUILD_PAIR_STRING("contentType", o->content_type ?: ""),
                                SD_JSON_BUILD_PAIR_STRING("question", o->question ?: ""),
                                SD_JSON_BUILD_PAIR_UNSIGNED("request", o->request_id),
                                SD_JSON_BUILD_PAIR_UNSIGNED("connection", o->connection_id),
                                SD_JSON_BUILD_PAIR_UNSIGNED("bodySize", o->body_size),
                                SD_JSON_BUILD_PAIR_UNSIGNED("dnsId", o->dns_id),
                                SD_JSON_BUILD_PAIR_BOOLEAN("haveDnsId", o->have_dns_id),
                                SD_JSON_BUILD_PAIR_BOOLEAN("hasOpt", o->has_opt),
                                SD_JSON_BUILD_PAIR_BOOLEAN("doBit", o->do_bit),
                                SD_JSON_BUILD_PAIR_INTEGER("responseDnsRcode", o->response_dns_rcode),
                                SD_JSON_BUILD_PAIR_UNSIGNED("responseStatus", o->response_status));
                if (r < 0)
                        return r;
        }

        if (!counts) {
                r = sd_json_variant_new_array(&counts, NULL, 0);
                if (r < 0)
                        return r;
        }
        if (!history) {
                r = sd_json_variant_new_array(&history, NULL, 0);
                if (r < 0)
                        return r;
        }

        r = sd_json_buildo(
                        &root,
                        SD_JSON_BUILD_PAIR_UNSIGNED("requests", c->n_requests),
                        SD_JSON_BUILD_PAIR_UNSIGNED("activeRequests", c->n_active),
                        SD_JSON_BUILD_PAIR_UNSIGNED("connections", g_hash_table_size(c->connections)),
                        SD_JSON_BUILD_PAIR_VARIANT("counts", counts),
                        SD_JSON_BUILD_PAIR_VARIANT("history", history));
        if (r < 0)
                return r;

        return sd_json_variant_format(root, 0, ret);
}

static void respond_state(ServerContext *c, SoupServerMessage *message) {
        _cleanup_free_ char *json = NULL;
        int r;

        assert(c);
        assert(message);

        r = make_state_json(c, &json);
        if (r < 0) {
                respond_plain(message, SOUP_STATUS_INTERNAL_SERVER_ERROR, "Failed to serialize state\n");
                return;
        }

        soup_server_message_set_status(message, SOUP_STATUS_OK, NULL);
        soup_server_message_set_response(message, "application/json", SOUP_MEMORY_COPY, json, strlen(json));
}

static void release_paused_requests(ServerContext *c) {
        g_autoptr(GList) messages = NULL;

        assert(c);

        messages = g_hash_table_get_keys(c->paused_messages);
        if (messages)
                log_info("Releasing %u paused DNS-over-HTTPS request(s).", g_list_length(messages));

        for (GList *i = messages; i; i = i->next) {
                SoupServerMessage *message = i->data;

                g_object_ref(message);

                respond_plain(message, SOUP_STATUS_SERVICE_UNAVAILABLE, "Reset\n");
                request_done(c, message, "was released by a state reset");
                soup_server_message_unpause(message);
                g_object_unref(message);
        }
}

static void reset_state(ServerContext *c) {
        assert(c);

        release_paused_requests(c);
        g_hash_table_remove_all(c->request_counts);
        g_hash_table_remove_all(c->connections);
        g_ptr_array_set_size(c->history, 0);
        c->n_requests = 0;
        c->next_connection_id = 1;
}

static int http_status_for_path(const char *path) {
        static const struct {
                const char *path;
                int status;
        } statuses[] = {
                { "/http/408", SOUP_STATUS_REQUEST_TIMEOUT },
                { "/http/421", SOUP_STATUS_MISDIRECTED_REQUEST },
                { "/http/425", 425 },
                { "/http/429", 429 },
                { "/http/500", SOUP_STATUS_INTERNAL_SERVER_ERROR },
                { "/http/502", SOUP_STATUS_BAD_GATEWAY },
                { "/http/503", SOUP_STATUS_SERVICE_UNAVAILABLE },
                { "/http/504", SOUP_STATUS_GATEWAY_TIMEOUT },
        };

        FOREACH_ELEMENT(i, statuses)
                if (streq(path, i->path))
                        return i->status;

        return 0;
}

static void handle_dns_request(ServerContext *c, SoupServerMessage *message, const char *path, DnsPacket *query, RequestObservation *observation, uint64_t request_number) {

        _cleanup_(dns_packet_unrefp) DnsPacket *reply = NULL;
        _cleanup_(dns_question_unrefp) DnsQuestion *wrong_question = NULL;
        _cleanup_free_ uint8_t *oversized = NULL;
        const char *content_type = "application/dns-message", *age = NULL;
        bool duplicate_content_type = false, duplicate_age = false;
        int r, rcode = DNS_RCODE_SUCCESS, status;

        assert(c);
        assert(message);
        assert(path);
        assert(query);
        assert(observation);

        status = http_status_for_path(path);
        if (status > 0) {
                observation->response_status = status;
                respond_plain(message, status, "HTTP failure\n");
                return;
        }

        if (streq(path, "/redirect")) {
                observation->response_status = SOUP_STATUS_FOUND;
                soup_server_message_set_redirect(message, SOUP_STATUS_FOUND, "/dns-query");
                return;
        }

        if (streq(path, "/disconnect") || (streq(path, "/retry/disconnect") && request_number == 1)) {
                GSocket *socket = soup_server_message_get_socket(message);

                log_info("Request #%" PRIu64 " is deliberately closing connection #%" PRIu64 ".",
                         observation->request_id, observation->connection_id);
                request_done(c, message, "deliberately closed its connection");
                if (socket)
                        (void) g_socket_close(socket, NULL);
                return;
        }

        if (streq(path, "/hang")) {
                g_signal_connect(message, "finished", G_CALLBACK(on_paused_request_finished), c);
                g_hash_table_insert(c->paused_messages, message, g_object_ref(message));
                log_info("Request #%" PRIu64 " is paused until the client cancels it or the server state is reset.",
                          observation->request_id);
                soup_server_message_pause(message);
                return;
        }

        if (streq(path, "/retry/http-502") && request_number == 1) {
                observation->response_status = SOUP_STATUS_BAD_GATEWAY;
                respond_plain(message, SOUP_STATUS_BAD_GATEWAY, "Retry once\n");
                return;
        }

        if (streq(path, "/dns-query/nxdomain"))
                rcode = DNS_RCODE_NXDOMAIN;
        else if (streq(path, "/dns-query/servfail"))
                rcode = DNS_RCODE_SERVFAIL;
        else if (streq(path, "/dns-query/retry-without-do") && observation->do_bit)
                rcode = DNS_RCODE_SERVFAIL;
        else if (streq(path, "/dns-query/retry-without-edns") && observation->has_opt)
                rcode = DNS_RCODE_FORMERR;
        else if (streq(path, "/dns/wrong-question")) {
                r = make_question(dns_question_first_key(query->question), "wrong.doh.test", &wrong_question);
                if (r < 0)
                        goto fail;
        }

        r = make_dns_reply(query, wrong_question, rcode, streq(path, "/dns-query/retry-without-edns") && observation->has_opt, &reply);
        if (r < 0)
                goto fail;
        observation->response_dns_rcode = dns_packet_rcode(reply);

        if (streq(path, "/content-type/missing"))
                content_type = NULL;
        else if (streq(path, "/content-type/wrong") || (streq(path, "/sequence/content-type-wrong") && request_number > 1))
                content_type = "application/json";
        else if (streq(path, "/content-type/parameter"))
                content_type = "application/dns-message; charset=utf-8";
        else if (streq(path, "/content-type/duplicate"))
                duplicate_content_type = true;
        else if (streq(path, "/dns-query/aged"))
                age = "60";
        else if (streq(path, "/dns-query/aged-expired"))
                age = "300";
        else if (streq(path, "/age/malformed"))
                age = "invalid";
        else if (streq(path, "/age/duplicate")) {
                age = "60";
                duplicate_age = true;
        } else if (streq(path, "/age/zero"))
                age = "0";
        else if (streq(path, "/age/overflow"))
                age = "184467440737095516160";

        observation->response_status = SOUP_STATUS_OK;

        if (streq(path, "/dns/empty")) {
                soup_server_message_set_status(message, SOUP_STATUS_OK, NULL);
                soup_message_headers_append(soup_server_message_get_response_headers(message), "Content-Type", content_type);
                set_response_body(message, NULL, 0);
                return;
        }
        if (streq(path, "/dns/malformed")) {
                static const uint8_t malformed[] = { 0, 0, 0, 0, 0, 1 };

                soup_server_message_set_status(message, SOUP_STATUS_OK, NULL);
                soup_message_headers_append(soup_server_message_get_response_headers(message), "Content-Type", content_type);
                set_response_body(message, malformed, sizeof(malformed));
                return;
        }
        if (streq(path, "/dns/truncated")) {
                assert(reply->size > 0);
                reply->size--;
        } else if (streq(path, "/dns/oversized")) {
                oversized = new0(uint8_t, DNS_PACKET_SIZE_MAX + 1U);
                if (!oversized)
                        goto fail;

                soup_server_message_set_status(message, SOUP_STATUS_OK, NULL);
                soup_message_headers_append(soup_server_message_get_response_headers(message), "Content-Type", content_type);
                set_response_body(message, oversized, DNS_PACKET_SIZE_MAX + 1U);
                return;
        } else if (streq(path, "/dns/wrong-id"))
                DNS_PACKET_HEADER(reply)->id = htobe16(1);
        else if (streq(path, "/dns/tc"))
                DNS_PACKET_HEADER(reply)->flags |= htobe16(DNS_PACKET_FLAG_TC);

        respond_dns_packet(message, reply, content_type, age, duplicate_content_type, duplicate_age);
        return;

fail:
        log_error_errno(r, "Failed to prepare the response for request #%" PRIu64 ": %m", observation->request_id);
        observation->response_status = SOUP_STATUS_INTERNAL_SERVER_ERROR;
        respond_plain(message, SOUP_STATUS_INTERNAL_SERVER_ERROR, "Failed to build DNS response\n");
}

static bool path_is_known(const char *path) {
        static const char * const paths[] = {
                "/dns-query",
                "/dns-query/aged",
                "/dns-query/aged-expired",
                "/dns-query/nxdomain",
                "/dns-query/servfail",
                "/dns-query/retry-without-do",
                "/dns-query/retry-without-edns",
                "/content-type/missing",
                "/content-type/wrong",
                "/content-type/parameter",
                "/content-type/duplicate",
                "/sequence/content-type-wrong",
                "/age/missing",
                "/age/malformed",
                "/age/duplicate",
                "/age/zero",
                "/age/overflow",
                "/dns/empty",
                "/dns/malformed",
                "/dns/truncated",
                "/dns/oversized",
                "/dns/wrong-id",
                "/dns/wrong-question",
                "/dns/tc",
                "/redirect",
                "/disconnect",
                "/hang",
                "/retry/http-502",
                "/retry/disconnect",
        };

        FOREACH_ELEMENT(i, paths)
                if (streq(path, *i))
                        return true;

        return http_status_for_path(path) > 0;
}

static void on_request(SoupServer *server, SoupServerMessage *message, const char *path, GHashTable *query_parameters, gpointer userdata) {
        ServerContext *c = userdata;
        _cleanup_(dns_packet_unrefp) DnsPacket *query = NULL;
        RequestObservation *observation;
        char key_str[DNS_RESOURCE_KEY_STRING_MAX];
        uint64_t request_number;
        int r;

        assert(c);
        assert(message);
        assert(path);

        if (streq(path, "/state")) {
                log_debug("Serving test server state: %" PRIu64 " requests, %u active, %u connections.",
                          c->n_requests, c->n_active, g_hash_table_size(c->connections));
                respond_state(c, message);
                return;
        }

        if (streq(path, "/reset")) {
                log_info("Resetting DNS-over-HTTPS test server state.");
                reset_state(c);
                soup_server_message_set_status(message, SOUP_STATUS_NO_CONTENT, NULL);
                return;
        }

        r = request_dns_packet(message, &query);
        observation = record_request(c, message, path, query);
        request_number = *(uint64_t*) g_hash_table_lookup(c->request_counts, path);
        if (query)
                log_info("Received request #%" PRIu64 " on connection #%" PRIu64
                         ": %s %s HTTP/%s for <%s>, DNS ID %u, body size %" PRIu64 ".",
                         observation->request_id, observation->connection_id, observation->method, observation->path, observation->http_version,
                         dns_resource_key_to_string(dns_question_first_key(query->question), key_str, sizeof(key_str)),
                         observation->dns_id, observation->body_size);
        else
                log_info("Received invalid request #%" PRIu64 " on connection #%" PRIu64
                         ": %s %s HTTP/%s, body size %" PRIu64 ".",
                         observation->request_id, observation->connection_id, observation->method, observation->path,
                         observation->http_version, observation->body_size);
        log_debug("Request #%" PRIu64 " headers: Accept=%s, Content-Type=%s",
                  observation->request_id, strna(observation->accept), strna(observation->content_type));

        if (r < 0) {
                log_info_errno(r, "Rejecting request #%" PRIu64 ": %m", observation->request_id);
                observation->response_status = r == -EOPNOTSUPP ? SOUP_STATUS_METHOD_NOT_ALLOWED : SOUP_STATUS_BAD_REQUEST;
                respond_plain(message, observation->response_status, "Invalid DNS-over-HTTPS request\n");
                return;
        }

        if (!path_is_known(path)) {
                log_info("Rejecting request #%" PRIu64 " for unknown endpoint %s.", observation->request_id, path);
                observation->response_status = SOUP_STATUS_NOT_FOUND;
                respond_plain(message, SOUP_STATUS_NOT_FOUND, "Unknown test endpoint\n");
                return;
        }

        handle_dns_request(c, message, path, query, observation, request_number);
}

static gboolean on_signal(gpointer userdata) {
        ServerContext *c = userdata;

        assert(c);
        assert(c->loop);

        log_notice("Stopping DNS-over-HTTPS test server after %" PRIu64 " request(s).", c->n_requests);
        g_main_loop_quit(c->loop);
        return G_SOURCE_REMOVE;
}

static int run_self_test(void) {
        static const uint8_t query_data[] = {
                0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
                0x00, 0x01, 0x00, 0x01,
        };
        static const uint8_t url_characters[] = { 0xfb, 0xff };
        uint8_t invalid_query[sizeof(query_data) + 1];
        _cleanup_(dns_packet_unrefp) DnsPacket *query = NULL, *query_aaaa = NULL, *reply = NULL, *reply_aaaa = NULL;
        _cleanup_free_ char *encoded = NULL;
        _cleanup_free_ void *decoded = NULL;
        DnsResourceRecord *candidate, *rr = NULL;
        size_t decoded_size;

        assert_se(base64urlmem(url_characters, sizeof(url_characters), &encoded) == 3);
        assert_se(streq(encoded, "-_8"));
        assert_se(decode_base64url(encoded, &decoded, &decoded_size) >= 0);
        assert_se(decoded_size == sizeof(url_characters));
        assert_se(memcmp(decoded, url_characters, decoded_size) == 0);

        encoded = mfree(encoded);
        decoded = mfree(decoded);
        assert_se(base64urlmem(query_data, sizeof(query_data), &encoded) > 0);
        assert_se(!strchr(encoded, '='));
        assert_se(decode_base64url(encoded, &decoded, &decoded_size) >= 0);
        assert_se(decoded_size == sizeof(query_data));
        assert_se(memcmp(decoded, query_data, decoded_size) == 0);

        assert_se(dns_packet_from_bytes(decoded, decoded_size, &query) >= 0);
        assert_se(streq(dns_question_first_name(query->question), "example.com"));
        assert_se(be16toh(DNS_PACKET_ID(query)) == 0);
        assert_se(make_dns_reply(query, NULL, DNS_RCODE_SUCCESS, false, &reply) >= 0);
        assert_se(dns_packet_validate_reply(reply) > 0);
        assert_se(dns_packet_extract(reply) >= 0);
        assert_se(dns_question_is_equal(query->question, reply->question) > 0);
        assert_se(dns_answer_size(reply->answer) == 1);

        DNS_ANSWER_FOREACH(candidate, reply->answer) {
                rr = candidate;
                break;
        }
        assert_se(rr);
        assert_se(rr->ttl == DNS_TEST_TTL);
        assert_se(rr->key->type == DNS_TYPE_A);
        assert_se(rr->a.in_addr.s_addr == htobe32(UINT32_C(0xc0000201)));
        reply = dns_packet_unref(reply);
        assert_se(make_dns_reply(query, NULL, DNS_RCODE_SERVFAIL, false, &reply) >= 0);
        assert_se(dns_packet_rcode(reply) == DNS_RCODE_SERVFAIL);

        memcpy(invalid_query, query_data, sizeof(query_data));
        invalid_query[sizeof(query_data) - 3] = DNS_TYPE_AAAA;
        assert_se(dns_packet_from_bytes(invalid_query, sizeof(query_data), &query_aaaa) >= 0);
        assert_se(make_dns_reply(query_aaaa, NULL, DNS_RCODE_SUCCESS, false, &reply_aaaa) >= 0);
        assert_se(dns_packet_extract(reply_aaaa) >= 0);
        assert_se(dns_answer_size(reply_aaaa->answer) == 1);
        rr = NULL;
        DNS_ANSWER_FOREACH(candidate, reply_aaaa->answer) {
                rr = candidate;
                break;
        }
        assert_se(rr);
        assert_se(rr->key->type == DNS_TYPE_AAAA);

        memcpy(invalid_query, query_data, sizeof(query_data));
        invalid_query[sizeof(query_data)] = 0;
        assert_se(dns_packet_from_bytes(invalid_query, sizeof(invalid_query), &query) == -EBADMSG);
        invalid_query[0] = 1;
        assert_se(dns_packet_from_bytes(invalid_query, sizeof(query_data), &query) == -EBADMSG);

        assert_se(decode_base64url("A", &decoded, &decoded_size) == -EINVAL);
        assert_se(decode_base64url("AA==", &decoded, &decoded_size) == -EINVAL);

        return 0;
}

static int run(int argc, char *argv[]) {
        g_autoptr(GError) error = NULL;
        g_autoptr(GInetAddress) inet_address = NULL;
        g_autoptr(GSocketAddress) socket_address = NULL;
        g_autoptr(GTlsCertificate) certificate = NULL;
        g_autoptr(SoupServer) server = NULL;
        g_autoptr(GMainLoop) loop = NULL;
        g_autofree char *uri_string = NULL;
        _cleanup_(uri_list_freep) GSList *uris = NULL;
        ServerContext context = {};
        uint16_t port;
        int r;

        g_setenv("SOUP_SERVER_HTTP2", "1", TRUE);
        log_setup();

        if (endswith(argv[0], "-self-test"))
                return run_self_test();

        if (argc != 5)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Expected ADDRESS PORT CERTIFICATE PRIVATE-KEY arguments.");

        inet_address = g_inet_address_new_from_string(argv[1]);
        if (!inet_address)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Listen address must be numeric: %s", argv[1]);

        r = safe_atou16(argv[2], &port);
        if (r < 0)
                return log_error_errno(r, "Invalid listen port '%s': %m", argv[2]);

        certificate = g_tls_certificate_new_from_files(argv[3], argv[4], &error);
        if (!certificate)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to load TLS certificate: %s", error->message);

        server = soup_server_new(NULL, NULL);
        loop = g_main_loop_new(NULL, false);

        context.server = server;
        context.loop = loop;
        server_context_init(&context);

        soup_server_set_tls_certificate(server, certificate);
        soup_server_add_handler(server, NULL, on_request, &context, NULL);
        g_signal_connect(server, "request-finished", G_CALLBACK(on_request_finished), &context);
        g_signal_connect(server, "request-aborted", G_CALLBACK(on_request_aborted), &context);

        socket_address = g_inet_socket_address_new(inet_address, port);
        if (!soup_server_listen(server, socket_address, SOUP_SERVER_LISTEN_HTTPS, &error)) {
                r = log_error_errno(SYNTHETIC_ERRNO(EADDRINUSE), "Failed to listen: %s", error->message);
                goto finish;
        }

        uris = soup_server_get_uris(server);
        if (!uris) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to determine listening URI.");
                goto finish;
        }

        uri_string = g_uri_to_string(uris->data);

        (void) g_unix_signal_add(SIGINT, on_signal, &context);
        (void) g_unix_signal_add(SIGTERM, on_signal, &context);

        log_notice("Listening for DNS-over-HTTPS requests on %s", uri_string);
        (void) sd_notifyf(false, "READY=1\nSTATUS=Listening on %s", uri_string);

        g_main_loop_run(loop);
        r = 0;

finish:
        soup_server_disconnect(server);
        server_context_done(&context);
        return r;
}

DEFINE_MAIN_FUNCTION(run);
