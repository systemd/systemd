/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "fileio.h"
#include "memory-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "web-util.h"

bool http_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        p = STARTSWITH_SET(url, "http://", "https://");
        if (!p)
                return false;

        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}

bool file_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        p = startswith(url, "file:/");
        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}

int provider_url_parse(const char *url, char **ret_socket, char **ret_resource) {
        const char *p, *e;
        int r;

        /* Parses a URL of the form "provider:[/path/to/socket]/resource", which refers to a resource
         * offered by a local Varlink service implementing the io.systemd.ResourceProvider interface on the
         * specified AF_UNIX socket. The socket path must be absolute and normalized. The resource name is
         * an opaque identifier that may contain slashes, but must not be empty, absolute, or contain
         * control characters, "." or ".." components. Query and fragment separators are not permitted
         * either, so that generic URL path manipulation works reliably on the resource name. */

        if (isempty(url))
                return -EINVAL;

        p = startswith(url, "provider:[");
        if (!p)
                return -EINVAL;

        e = strchr(p, ']');
        if (!e || e == p)
                return -EINVAL;
        if (e[1] != '/')
                return -EINVAL;

        _cleanup_free_ char *s = strndup(p, e - p);
        if (!s)
                return -ENOMEM;

        if (!path_is_absolute(s) || !path_is_normalized(s))
                return -EINVAL;

        const char *resource = e + 2;
        if (isempty(resource))
                return -EINVAL;
        if (path_is_absolute(resource) || !path_is_normalized(resource))
                return -EINVAL;
        if (string_has_cc(resource, /* ok= */ NULL) || strpbrk(resource, "?#"))
                return -EINVAL;

        r = strdup_to_full(ret_resource, resource);
        if (r < 0)
                return r;

        if (ret_socket)
                *ret_socket = TAKE_PTR(s);

        return 0;
}

bool provider_url_is_valid(const char *url) {
        return provider_url_parse(url, /* ret_socket= */ NULL, /* ret_resource= */ NULL) >= 0;
}

bool documentation_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        if (http_url_is_valid(url) || file_url_is_valid(url))
                return true;

        p = STARTSWITH_SET(url, "info:", "man:");
        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}

bool http_header_valid(const char *header) {
        return header &&
                ascii_is_valid(header) &&
                !string_has_cc(header, /* ok= */ NULL) &&
                strchr(header, ':');
}

bool http_etag_is_valid(const char *etag) {
        if (isempty(etag))
                return false;

        if (!endswith(etag, "\""))
                return false;

        if (!STARTSWITH_SET(etag, "\"", "W/\""))
                return false;

        return true;
}

/* The characters permitted in an HTTP field name, i.e. "tchar" as per RFC 9110, section 5.6.2 */
#define HTTP_TCHAR LETTERS DIGITS "!#$%&'*+-.^_`|~"

bool http_field_name_is_valid(const char *name) {
        /* Checks whether the specified string is a valid HTTP field name (i.e. header name) as per RFC
         * 9110, section 5.1 */

        return !isempty(name) && in_charset(name, HTTP_TCHAR);
}

bool http_field_value_is_valid(const char *value) {
        /* Checks whether the specified string is a valid HTTP field value as per RFC 9110, section 5.5,
         * i.e. consists of visible characters, spaces and horizontal tabs only. In particular this refuses
         * CR and LF, so that a value cannot be used to inject additional fields. Bytes ≥ 0x80 are permitted
         * ("obs-text"), so that UTF-8 is passed through. An empty value is valid. */

        return value && !string_has_cc(value, /* ok= */ "\t");
}

bool http_field_name_is_client_owned(const char *name) {
        /* Returns true for HTTP request fields we manage ourselves (or that curl manages on our behalf),
         * because they relate to connection management, transfer and content encoding, ranges,
         * caching or proxying, and which hence must not be set from external sources, i.e. via the
         * "httpHeaders" field of UAPI.16 manifests. */

        return name && STRCASE_IN_SET(name,
                                      "Accept-Encoding",
                                      "Connection",
                                      "Content-Encoding",
                                      "Content-Length",
                                      "Expect",
                                      "Host",
                                      "If-Match",
                                      "If-Modified-Since",
                                      "If-None-Match",
                                      "If-Range",
                                      "If-Unmodified-Since",
                                      "Keep-Alive",
                                      "Proxy-Authorization",
                                      "Proxy-Connection",
                                      "Range",
                                      "TE",
                                      "Trailer",
                                      "Transfer-Encoding",
                                      "Upgrade");
}

int http_url_get_origin(const char *url, char **ret) {
        const char *p, *scheme;
        uint16_t port;

        assert(ret);

        /* Determines the origin (as per RFC 6454) of an http:// or https:// URL, and returns it in
         * normalized form, i.e. as "scheme://host:port", with scheme and host lowercased and the port always
         * spelled out explicitly. Two URLs have the same origin if the returned strings are equal. Any user
         * information in the URL is dropped, as it is not part of the origin. Returns -EINVAL for URLs of
         * other schemes or that we cannot parse. Note that we deliberately do not attempt to normalize
         * host names further (i.e. no IDNA or percent-decoding), as the origin is used to decide whether to
         * send sensitive data to a host, and hence it is safer to consider equivalent but differently
         * spelled hosts as different. */

        if (!url)
                return -EINVAL;

        if ((p = startswith_no_case(url, "http://"))) {
                scheme = "http";
                port = 80;
        } else if ((p = startswith_no_case(url, "https://"))) {
                scheme = "https";
                port = 443;
        } else
                return -EINVAL;

        _cleanup_free_ char *authority = strndup(p, strcspn(p, "/?#"));
        if (!authority)
                return -ENOMEM;

        /* Drop the user information, if there is any. Note that the user information may contain an
         * unescaped "@" in practice, hence split at the last one, as the host part may not contain any. */
        char *host = strrchr(authority, '@');
        host = host ? host + 1 : authority;

        char *port_string = NULL;
        if (host[0] == '[') {
                /* An IPv6 address literal, possibly followed by a port */
                char *e = strchr(host, ']');
                if (!e)
                        return -EINVAL;

                if (e[1] == ':') {
                        e[1] = 0;
                        port_string = e + 2;
                } else if (e[1] != 0)
                        return -EINVAL;
        } else {
                port_string = strrchr(host, ':');
                if (port_string)
                        *(port_string++) = 0;
        }

        if (isempty(host) || string_has_cc(host, /* ok= */ NULL) || !ascii_is_valid(host))
                return -EINVAL;

        /* An empty port is equivalent to the scheme's default port as per RFC 3986, section 3.2.3 */
        if (!isempty(port_string)) {
                if (!in_charset(port_string, DIGITS))
                        return -EINVAL;

                if (safe_atou16_full(port_string, 10, &port) < 0 || port == 0)
                        return -EINVAL;
        }

        if (asprintf(ret, "%s://%s:%" PRIu16, scheme, ascii_strlower(host), port) < 0)
                return -ENOMEM;

        return 0;
}

int http_headers_parse(FILE *f, char ***ret) {
        int r;

        assert(f);
        assert(ret);

        /* Reads HTTP header fields in the format HTTP itself uses (RFC 9110, section 5), i.e. one
         * "Name: value" field per line, into a strv of name/value pairs. Lines may be terminated by LF or
         * CRLF, empty lines are ignored. Optional whitespace around the value is dropped. Field names must
         * be unique (compared case-insensitively). Obsolete line folding is not supported. Note that we
         * deliberately do not log the values here, they might carry credentials. */

        _cleanup_strv_free_erase_ char **l = NULL;
        size_t n = 0;
        for (;;) {
                _cleanup_(erase_and_freep) char *line = NULL;
                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (isempty(line))
                        continue;

                _cleanup_free_ char *name = NULL;
                _cleanup_(erase_and_freep) char *value = NULL;
                r = split_pair(line, ":", &name, &value);
                if (r < 0)
                        return r;

                if (!http_field_name_is_valid(name))
                        return -EINVAL;

                /* Drop the optional whitespace ("OWS") around the value */
                const char *v = delete_trailing_chars(skip_leading_chars(value, " \t"), " \t");
                if (!http_field_value_is_valid(v))
                        return -EINVAL;

                STRV_FOREACH_PAIR(a, b, l)
                        if (strcaseeq(*a, name))
                                return -ENOTUNIQ;

                if (n >= HTTP_HEADERS_MAX)
                        return -E2BIG;

                r = strv_extend_many(&l, name, v);
                if (r < 0)
                        return r;

                n++;
        }

        *ret = TAKE_PTR(l);
        return 0;
}

int http_headers_format(char * const *headers, char **ret) {
        assert(ret);

        /* The inverse of http_headers_parse(): formats a strv of name/value pairs as one "Name: value"
         * line per field */

        _cleanup_(erase_and_freep) char *s = NULL;
        STRV_FOREACH_PAIR(a, b, headers) {
                if (!http_field_name_is_valid(*a) || !http_field_value_is_valid(*b))
                        return -EINVAL;

                if (!strextend(&s, *a, ": ", *b, "\n"))
                        return -ENOMEM;
        }

        if (!s) {
                s = strdup("");
                if (!s)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(s);
        return 0;
}

int parse_content_range(const char *s, uint64_t *ret_start, uint64_t *ret_end, uint64_t *ret_total) {
        uint64_t start, end, total;
        int r;

        assert(s);

        /* Parses the value of a "Content-Range:" header of a 206 response, i.e. "bytes START-END/TOTAL"
         * (RFC 9110, section 14.4). Only the "bytes" unit is supported. TOTAL may be "*" if the server
         * doesn't know it, in which case UINT64_MAX is returned for it. The unsatisfied-range form of 416
         * responses (where the range is replaced by an asterisk) is refused. All return parameters are
         * optional. Note that the numbers are always decimal, even with leading zeros (which RFC 9110
         * permits), hence explicitly parse them in base 10. */

        const char *p = startswith_no_case(s, "bytes ");
        if (!p)
                return -EINVAL;

        size_t n = strspn(p, DIGITS);
        if (n == 0 || p[n] != '-')
                return -EINVAL;

        _cleanup_free_ char *a = strndup(p, n);
        if (!a)
                return -ENOMEM;

        p += n + 1;
        n = strspn(p, DIGITS);
        if (n == 0 || p[n] != '/')
                return -EINVAL;

        _cleanup_free_ char *b = strndup(p, n);
        if (!b)
                return -ENOMEM;

        p += n + 1;

        r = safe_atou64_full(a, 10, &start);
        if (r < 0)
                return r;

        r = safe_atou64_full(b, 10, &end);
        if (r < 0)
                return r;

        if (end < start)
                return -EINVAL;

        if (streq(p, "*"))
                total = UINT64_MAX;
        else {
                if (isempty(p) || !in_charset(p, DIGITS))
                        return -EINVAL;

                r = safe_atou64_full(p, 10, &total);
                if (r < 0)
                        return r;

                if (end >= total)
                        return -EINVAL;
        }

        if (ret_start)
                *ret_start = start;
        if (ret_end)
                *ret_end = end;
        if (ret_total)
                *ret_total = total;
        return 0;
}
