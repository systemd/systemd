/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "af-list.h"
#include "extract-word.h"
#include "ip-protocol-list.h"
#include "parse-socket-bind-item.h"
#include "parse-util.h"

static int parse_af_token(
                const char *token,
                int *family,
                int *ip_protocol,
                uint16_t *nr_ports,
                uint16_t *port_min) {
        int af;

        assert(token);
        assert(family);

        af = af_from_ipv4_ipv6(token);
        if (af == AF_UNSPEC)
                return -EINVAL;

        *family = af;
        return 0;
}

static int parse_ip_protocol_token(
                const char *token,
                int *family,
                int *ip_protocol,
                uint16_t *nr_ports,
                uint16_t *port_min) {
        int proto;

        assert(token);
        assert(ip_protocol);

        proto = ip_protocol_from_tcp_udp(token);
        if (proto < 0)
                return -EINVAL;

        *ip_protocol = proto;
        return 0;
}

static int parse_ip_ports_token(
                const char *token,
                int *family,
                int *ip_protocol,
                uint16_t *nr_ports,
                uint16_t *port_min) {
        assert(token);
        assert(nr_ports);
        assert(port_min);

        if (streq(token, "any"))
                *nr_ports = *port_min = 0;
        else {
                uint16_t mn = 0, mx = 0;
                int r = parse_ip_port_range(token, &mn, &mx);
                if (r < 0)
                        return r;

                *nr_ports = mx - mn + 1;
                *port_min = mn;
        }

        return 0;
}

typedef int (*parse_token_f)(
                const char *,
                int *,
                int *,
                uint16_t *,
                uint16_t *);

int parse_socket_bind_item(
                const char *str,
                int *address_family,
                int *ip_protocol,
                uint16_t *nr_ports,
                uint16_t *port_min) {
        /* Order of token parsers is important. */
        const parse_token_f parsers[] = {
                &parse_af_token,
                &parse_ip_protocol_token,
                &parse_ip_ports_token,
        };
        parse_token_f const *parser_ptr = parsers;
        int af = AF_UNSPEC, proto = 0, r;
        uint16_t nr = 0, mn = 0;
        const char *p = str;

        assert(str);
        assert(address_family);
        assert(ip_protocol);
        assert(nr_ports);
        assert(port_min);

        if (isempty(p))
                return -EINVAL;

        for (;;) {
                _cleanup_free_ char *token = NULL;

                r = extract_first_word(&p, &token, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r == 0)
                        break;
                if (r < 0)
                        return r;

                if (isempty(token))
                        return -EINVAL;

                while (parser_ptr != parsers + ELEMENTSOF(parsers)) {
                        r = (*parser_ptr)(token, &af, &proto, &nr, &mn);
                        if (r == -ENOMEM)
                                return r;

                        ++parser_ptr;
                        /* Continue to next token if parsing succeeded,
                         * otherwise apply next parser to the same token.
                         */
                        if (r >= 0)
                                break;
                }
                if (parser_ptr == parsers + ELEMENTSOF(parsers))
                                break;
        }

        /* Failed to parse a token. */
        if (r < 0)
                return r;

        /* Parsers applied succesfully, but end of the string not reached. */
        if (p)
                return -EINVAL;

        *address_family = af;
        *ip_protocol = proto;
        *nr_ports = nr;
        *port_min = mn;
        return 0;
}
