/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if !ENABLE_DNS_OVER_HTTPS
#error This source file requires DNS-over-HTTPS to be enabled and OpenSSL to be available.
#endif

#include "resolved-dns-stream.h"
#include "resolved-dnshttps.h"
#include "resolved-manager.h"
#include "hexdecoct.h"
#include "build.h"
#include "llhttp.h"
#include "string.h"


static char *dnshttps_current_header_field = NULL;
static Hashmap *dnshttps_parser_data = NULL;


static int on_body_content(llhttp_t *parser, const char *at, size_t length) {
        int r;
        http_header *entry;
        entry = (http_header*)malloc(sizeof(http_header));
        entry->at = at;
        entry->len = length;

        HeaderFields enum_field;
        enum_field = BODY;

        r = hashmap_put(dnshttps_parser_data, UINT_TO_PTR(enum_field), entry);
        if (r < 0){
                log_debug_errno(r, "Failed to put body into HTTP response hashmap.");
                return r;
        }

        return 0;
}

static int on_header_field(llhttp_t *parser, const char *at, size_t length) {
        /* store in current header global */

        /* Allocate memory for dnshttps_current_header_field and add one extra byte for the null terminator */
        dnshttps_current_header_field = malloc(length + 1);
        if (dnshttps_current_header_field == NULL)
                return -ENOMEM;


        // Copy the data and null-terminate the string
        strncpy(dnshttps_current_header_field, at, length);
        dnshttps_current_header_field[length] = '\0';

        return 0;
}

static int on_header_value(llhttp_t *parser, const char *at, size_t length) {
        int r;
        /* use global to populate the hashmap */
        /* need clean up / free current_header_field */

        http_header *entry;
        entry = (http_header*)malloc(sizeof(http_header));
        entry->at = at;
        entry->len = length;

        HeaderFields enum_field;

        r = strcmp(dnshttps_current_header_field, "Server");
        if (r == 0) {
                enum_field = SERVER;
        }

        r = hashmap_put(dnshttps_parser_data, UINT_TO_PTR(enum_field), entry);

        return 0;
}


int dnshttps_stream_extract_dns(DnsStream *s) {
        int status, r;
        _cleanup_free_ char *header_copy = NULL;


        /* Our HTTP data at this moment */
        uint8_t *p_data;
        p_data = DNS_PACKET_DATA(s->read_packet);

        /* Our buffer to work on the HTTP data' */
        _cleanup_free_ char *http_response_buf = NULL;
        http_response_buf = malloc(s->read_packet->size);
        memcpy(http_response_buf, p_data, s->read_packet->size);


        /* Start parsing the HTTP */
        r = hashmap_ensure_allocated(&dnshttps_parser_data, NULL);
        if (r < 0)
                return r;

        r = hashmap_ensure_allocated(&s->response_headers, NULL);
        if (r < 0)
                return r;

        // trying llhttp

        /* TODO: This is a workaround until I figure out why we lost the fist
           two chars of the HTTP resonse. Possibly due the lack of a dedicated buffer
           to the HTTP response before move raw dns data to the s->read_packet */
        char llhttp_response[1024] = "HT";

        memcpy(&llhttp_response[2], http_response_buf, 1022);

        llhttp_t parser;
        llhttp_settings_t settings;

        r = hashmap_put(dnshttps_parser_data, &parser, s->response_headers);
        if (r < 0) {
                return r;
        }



        /*Initialize user callbacks and settings */
        llhttp_settings_init(&settings);

        /*Set user callback */
        settings.on_header_field = on_header_field;
        settings.on_header_value = on_header_value;
        settings.on_body = on_body_content;

        // Set parser hashmap to store headers and values
        r = hashmap_put(s->response_headers, &parser, NULL);
        if (r < 0)
                return r;

        /*Initialize the parser in HTTP_BOTH mode, meaning that it will select between
        *HTTP_REQUEST and HTTP_RESPONSE parsing automatically while reading the first
        *input.
        */
        llhttp_init(&parser, HTTP_BOTH, &settings);

        /*Parse request! */

        enum llhttp_errno err = llhttp_execute(&parser, &llhttp_response[0], 1024);
        if (err == HPE_OK) {
                fprintf(stdout, "Successfully parsed!\n");
        } else {
                fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), parser.reason);
        }

        status = llhttp_get_status_code(&parser);

        switch (status){
        case 200:
                puts("HTTP 200 ok, proceeding...");
                break;
        case 400:
                puts("HTTP 400...");
                return -EINVAL;
                break;
        case 414:
                puts("HTTP 414, URI too big...");
                return -EINVAL;
                break;
        case 429:
                puts("HTTP 429, too many requests...");
                return -EINVAL;
                break;
        case 500:
                puts("HTTP 500, internal server error...");
                return DNS_TRANSACTION_ABORTED;
                break;
        default:
                printf("\n\nHTTP not ok, fail now, reponse code: %d", status);
                /* TODO: handle errors */
                break;
        }


        HeaderFields enum_get;
        http_header *ret_entry;
        enum_get = BODY;
        ret_entry = hashmap_get(dnshttps_parser_data, UINT_TO_PTR(enum_get));

        /* trying to replace http packet with dns packet from body */
        /* FIGURE OUT THE ACTUAL PACKET SIZE */

        /* memset(p_data, 0, ret_entry->len); */
        memset(p_data, 0, s->read_packet->size);
        memcpy(p_data, ret_entry->at, ret_entry->len);

        /* clean up hashmaps */
        hashmap_remove(dnshttps_parser_data, &parser);
        enum_get = SERVER;
        hashmap_remove(dnshttps_parser_data, UINT_TO_PTR(enum_get));
        enum_get = BODY;
        hashmap_remove(dnshttps_parser_data, UINT_TO_PTR(enum_get));

        return 0;

}

/* should take the packet wire format and construct a http request, wire format*/
int dnshttps_packet_to_base64url(DnsTransaction *t){
        printf("\n in tcp, about to make base64url...\n");

        uint8_t *p_data = DNS_PACKET_DATA(t->sent);
        size_t url_len;

        _cleanup_free_ char *dnshttps_url = NULL;

        /* puts("zeroing id..."); */
        p_data[0] = 0;
        p_data[1] = 0;

        /* TODO: what about base64url? Normal base64 seems to be working just fine*/
        int r = base64mem_full(p_data, t->sent->size, MAX_URL_LENGTH, &dnshttps_url);
        if (r < 0){
                log_debug_errno(r, "Failed to encode DNS packet to base64.");
                return r;
        }

        // clean base64 trailing charecters
        url_len = strlen(dnshttps_url);
        while (url_len > 0 && dnshttps_url[url_len - 1] == '=') {
                dnshttps_url[--url_len] = '\0';
        }


        char get_request[512] = "";
        char header_host[32] = "";
        snprintf(header_host, sizeof(header_host), "Host: %s\r\n", t->server->server_string);

        char header_agent[64] = "";
        snprintf(header_agent, sizeof(header_agent), "User-Agent: systemd-resolved/%s\r\n", STRINGIFY(PROJECT_VERSION));


        strcpy(get_request, "GET /dns-query?dns=");
        strcat(get_request, dnshttps_url);
        strcat(get_request, " HTTP/1.1\r\n");
        strcat(get_request, header_host);
        strcat(get_request, header_agent);
        strcat(get_request, "Accept: application/dns-message\r\n");
        strcat(get_request, "Connection: Close\r\n");
        strcat(get_request, "\r\n");

        puts(get_request);
        printf("assigning request to stream: %p\n", t->stream);
        strcpy(t->stream->dnshttps_sent, get_request);

        return 0;
}
