/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "af-list.h"
#include "extract-word.h"
#include "ip-protocol-list.h"
#include "log.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "utf8.h"

int path_simplify_and_warn(
                char *path,
                unsigned flag,
                const char *unit,
                const char *filename,
                unsigned line,
                const char *lvalue) {

        bool fatal = flag & PATH_CHECK_FATAL;

        assert(!FLAGS_SET(flag, PATH_CHECK_ABSOLUTE | PATH_CHECK_RELATIVE));

        if (!utf8_is_valid(path))
                return log_syntax_invalid_utf8(unit, LOG_ERR, filename, line, path);

        if (flag & (PATH_CHECK_ABSOLUTE | PATH_CHECK_RELATIVE)) {
                bool absolute;

                absolute = path_is_absolute(path);

                if (!absolute && (flag & PATH_CHECK_ABSOLUTE))
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                          "%s= path is not absolute%s: %s",
                                          lvalue, fatal ? "" : ", ignoring", path);

                if (absolute && (flag & PATH_CHECK_RELATIVE))
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                          "%s= path is absolute%s: %s",
                                          lvalue, fatal ? "" : ", ignoring", path);
        }

        path_simplify_full(path, flag & PATH_KEEP_TRAILING_SLASH ? PATH_SIMPLIFY_KEEP_TRAILING_SLASH : 0);

        if (!path_is_valid(path))
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "%s= path has invalid length (%zu bytes)%s.",
                                  lvalue, strlen(path), fatal ? "" : ", ignoring");

        if (!path_is_normalized(path))
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                  "%s= path is not normalized%s: %s",
                                  lvalue, fatal ? "" : ", ignoring", path);

        return 0;
}

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
                int r = parse_ip_port_range(token, &mn, &mx, true);
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
        const char *p = ASSERT_PTR(str);

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

        /* Parsers applied successfully, but end of the string not reached. */
        if (p)
                return -EINVAL;

        *address_family = af;
        *ip_protocol = proto;
        *nr_ports = nr;
        *port_min = mn;
        return 0;
}

int config_parse_path_or_ignore(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *n = NULL;
        bool fatal = ltype;
        char **s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue))
                goto finalize;

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        if (streq(n, "-"))
                goto finalize;

        r = path_simplify_and_warn(n, PATH_CHECK_ABSOLUTE | (fatal ? PATH_CHECK_FATAL : 0), unit, filename, line, lvalue);
        if (r < 0)
                return fatal ? -ENOEXEC : 0;

finalize:
        return free_and_replace(*s, n);
}
