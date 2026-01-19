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
        const char *host, *proto = "";

        host = STARTSWITH_SET(url, "http://", "https://");
        if (!host) {
                host = url;
                proto = "https://";
        }

        if (strchr(host, ':'))
                return strjoin(proto, url, "/upload");
        else {
                char *t;
                size_t x;

                t = strdupa_safe(url);
                x = strlen(t);
                while (x > 0 && t[x - 1] == '/')
                        t[x - 1] = '\0';

                return strjoin(proto, t, ":", port, "/upload");
        }
        return NULL;
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
