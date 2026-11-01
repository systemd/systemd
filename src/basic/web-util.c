/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
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

int parse_content_range(const char *s, uint64_t *ret_start, uint64_t *ret_end, uint64_t *ret_total) {
        uint64_t start, end, total;
        int r;

        assert(s);

        /* Parses the value of a "Content-Range:" header of a 206 response, i.e. "bytes START-END/TOTAL"
         * (RFC 9110, section 14.4). Only the "bytes" unit is supported. TOTAL may be "*" if the server
         * doesn't know it, in which case UINT64_MAX is returned for it. The unsatisfied-range form of 416
         * responses (where the range is replaced by an asterisk) is refused. All return parameters are
         * optional. */

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

        r = safe_atou64(a, &start);
        if (r < 0)
                return r;

        r = safe_atou64(b, &end);
        if (r < 0)
                return r;

        if (end < start)
                return -EINVAL;

        if (streq(p, "*"))
                total = UINT64_MAX;
        else {
                if (isempty(p) || !in_charset(p, DIGITS))
                        return -EINVAL;

                r = safe_atou64(p, &total);
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
