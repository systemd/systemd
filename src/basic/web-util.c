/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
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

        if (ret_resource) {
                char *r = strdup(resource);
                if (!r)
                        return -ENOMEM;

                *ret_resource = r;
        }

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
