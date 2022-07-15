/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

#include "nss-test-util.h"
#include "string-util.h"

const char* nss_status_to_string(enum nss_status status, char *buf, size_t buf_len) {
        switch (status) {
        case NSS_STATUS_TRYAGAIN:
                return "NSS_STATUS_TRYAGAIN";
        case NSS_STATUS_UNAVAIL:
                return "NSS_STATUS_UNAVAIL";
        case NSS_STATUS_NOTFOUND:
                return "NSS_STATUS_NOTFOUND";
        case NSS_STATUS_SUCCESS:
                return "NSS_STATUS_SUCCESS";
        case NSS_STATUS_RETURN:
                return "NSS_STATUS_RETURN";
        default:
                (void) snprintf(buf, buf_len, "%i", status);
                return buf;
        }
};

void* nss_open_handle(const char *dir, const char *module, int flags) {
        const char *path = NULL;
        void *handle;

        if (dir)
                path = strjoina(dir, "/libnss_", module, ".so.2");
        if (!path || access(path, F_OK) < 0)
                path = strjoina("libnss_", module, ".so.2");

        log_debug("Using %s", path);
        handle = dlopen(path, flags);
        if (!handle)
                log_error("Failed to load module %s: %s", module, dlerror());
        return handle;
}
