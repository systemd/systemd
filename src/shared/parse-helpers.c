/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "af-list.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "ip-protocol-list.h"
#include "log.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-table.h"
#include "string-util.h"
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

        path_simplify(path);

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

int open_file_parse(const char *v, OpenFile **ret) {
        _cleanup_free_ char *options = NULL;
        _cleanup_(open_file_freep) OpenFile *of = NULL;
        int r;

        assert(v);
        assert(ret);

        of = new0(OpenFile, 1);
        if (!of)
                return -ENOMEM;

        r = extract_many_words(&v, ":", EXTRACT_DONT_COALESCE_SEPARATORS|EXTRACT_CUNESCAPE, &of->path, &of->fdname, &options, NULL);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        /* Enforce that at most 3 colon-separated words are present */
        if (!isempty(v))
                return -EINVAL;

        for (const char *p = options;;) {
                OpenFileFlags flag;
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, ",", 0);
                if (r < 0)
                                return r;
                if (r == 0)
                        break;

                flag = open_file_flags_from_string(word);
                if (flag < 0)
                        return flag;

                if ((flag & ~_OPENFILE_MASK_PUBLIC) != 0)
                        return -EINVAL;

                if ((flag & of->flags) != 0)
                        return -EINVAL;

                of->flags |= flag;
        }

        if (isempty(of->fdname)) {
                free(of->fdname);
                r = path_extract_filename(of->path, &of->fdname);
                if (r < 0)
                        return r;
        }

        r = open_file_validate(of);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(of);

        return 0;
}

int open_file_validate(const OpenFile *of) {
        assert(of);

        if (!path_is_valid(of->path) || !path_is_absolute(of->path))
                return -EINVAL;

        if (!fdname_is_valid(of->fdname))
                return -EINVAL;

        if ((!!FLAGS_SET(of->flags, OPENFILE_READ_ONLY) + !!FLAGS_SET(of->flags, OPENFILE_APPEND) +
             !!FLAGS_SET(of->flags, OPENFILE_TRUNCATE)) > 1)
                return -EINVAL;

        return 0;
}

int open_file_to_string(const OpenFile *of, char **ret) {
        _cleanup_free_ char *options = NULL, *fname = NULL, *s = NULL;
        bool has_fdname = false;
        int r;

        assert(of);
        assert(ret);

        s = shell_escape(of->path, ":");
        if (!s)
                return -ENOMEM;

        r = path_extract_filename(of->path, &fname);
        if (r < 0)
                return r;

        has_fdname = !streq(fname, of->fdname);
        if (has_fdname)
                if (!strextend(&s, ":", of->fdname))
                        return -ENOMEM;

        for (OpenFileFlags flag = OPENFILE_READ_ONLY; flag < _OPENFILE_MAX; flag <<= 1)
                if (FLAGS_SET(of->flags, flag) && !strextend_with_separator(&options, ",", open_file_flags_to_string(flag)))
                        return -ENOMEM;

        if (options)
                if (!(has_fdname ? strextend(&s, ":", options) : strextend(&s, "::", options)))
                        return -ENOMEM;

        *ret = TAKE_PTR(s);

        return 0;
}

OpenFile* open_file_free(OpenFile *of) {
        if (!of)
                return NULL;

        free(of->path);
        free(of->fdname);
        return mfree(of);
}

static const char * const open_file_flags_table[_OPENFILE_MAX] = {
        [OPENFILE_READ_ONLY] = "read-only",
        [OPENFILE_APPEND]    = "append",
        [OPENFILE_TRUNCATE]  = "truncate",
        [OPENFILE_GRACEFUL]  = "graceful",
};

DEFINE_STRING_TABLE_LOOKUP(open_file_flags, OpenFileFlags);
