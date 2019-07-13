/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "sysctl-util.h"

char *sysctl_normalize(char *s) {
        char *n;

        n = strpbrk(s, "/.");
        /* If the first separator is a slash, the path is
         * assumed to be normalized and slashes remain slashes
         * and dots remains dots. */
        if (!n || *n == '/')
                return s;

        /* Otherwise, dots become slashes and slashes become
         * dots. Fun. */
        while (n) {
                if (*n == '.')
                        *n = '/';
                else
                        *n = '.';

                n = strpbrk(n + 1, "/.");
        }

        return s;
}

int sysctl_write(const char *property, const char *value) {
        char *p;
        _cleanup_close_ int fd = -1;

        assert(property);
        assert(value);

        log_debug("Setting '%s' to '%.*s'.", property, (int) strcspn(value, NEWLINE), value);

        p = strjoina("/proc/sys/", property);
        fd = open(p, O_WRONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!endswith(value, "\n"))
                value = strjoina(value, "\n");

        if (write(fd, value, strlen(value)) < 0)
                return -errno;

        return 0;
}

int sysctl_writef(const char *property, const char *format, ...) {
        _cleanup_free_ char *v = NULL;
        va_list ap;
        int r;

        va_start(ap, format);
        r = vasprintf(&v, format, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        return sysctl_write(property, v);
}

int sysctl_write_ip_property(int af, const char *ifname, const char *property, const char *value) {
        const char *p;

        assert(IN_SET(af, AF_INET, AF_INET6));
        assert(property);
        assert(value);

        p = strjoina("/proc/sys/net/ipv", af == AF_INET ? "4" : "6",
                     ifname ? "/conf/" : "", strempty(ifname),
                     property[0] == '/' ? "" : "/", property);

        log_debug("Setting '%s' to '%s'", p, value);

        return write_string_file(p, value, WRITE_STRING_FILE_VERIFY_ON_FAILURE | WRITE_STRING_FILE_DISABLE_BUFFER);
}

int sysctl_read(const char *property, char **content) {
        char *p;

        assert(property);
        assert(content);

        p = strjoina("/proc/sys/", property);
        return read_full_file(p, content, NULL);
}

int sysctl_read_ip_property(int af, const char *ifname, const char *property, char **ret) {
        _cleanup_free_ char *value = NULL;
        const char *p;
        int r;

        assert(IN_SET(af, AF_INET, AF_INET6));
        assert(property);

        p = strjoina("/proc/sys/net/ipv", af == AF_INET ? "4" : "6",
                     ifname ? "/conf/" : "", strempty(ifname),
                     property[0] == '/' ? "" : "/", property);

        r = read_one_line_file(p, &value);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(value);

        return r;
}
