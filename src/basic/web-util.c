/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>

#include "string-util.h"
#include "utf8.h"
#include "web-util.h"

bool http_etag_is_valid(const char *etag) {
        if (isempty(etag))
                return false;

        if (!endswith(etag, "\""))
                return false;

        if (!startswith(etag, "\"") && !startswith(etag, "W/\""))
                return false;

        return true;
}

bool http_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        p = startswith(url, "http://");
        if (!p)
                p = startswith(url, "https://");
        if (!p)
                return false;

        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}

bool documentation_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        if (http_url_is_valid(url))
                return true;

        p = startswith(url, "file:/");
        if (!p)
                p = startswith(url, "info:");
        if (!p)
                p = startswith(url, "man:");

        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}
