/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "web-util.h"

bool http_etag_is_valid(const char *etag) {
        if (isempty(etag))
                return false;

        if (!endswith(etag, "\""))
                return false;

        if (!STARTSWITH_SET(etag, "\"", "W/\""))
                return false;

        return true;
}

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

char* http_url_add_port(const char *url, const char *port) {

        assert(url);
        assert(port);
        const char *url_without_scheme, *scheme = "";
        _cleanup_free_ char *host = NULL, *path = NULL;

        const char *strport = strjoina(":", port);
        url_without_scheme = STARTSWITH_SET(url, "http://", "https://");
        if (url_without_scheme) {
                scheme = startswith(url, "https://") ? "https://" : "http://";
                host = strdup(url_without_scheme);
        } else {
                /* Default to the https scheme if the URL does not specify one */
                scheme = "https://";
                host = strdup(url);
        }
        if (!host) return NULL;

        delete_trailing_chars(host, "/");
        char *t = strchr(host, '/');
        if (t) {
                path = strdup(t);
                if (!path) return NULL;
                *t = '\0';
        }
        if (strchr(host,']')){
                if (strstr_ptr(host, "]:"))
                        strport = "";
        } else if (strchr(host, ':')){
                strport = "";
        }

        return strjoin(scheme, host, strport, strempty(path), "/upload");
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
