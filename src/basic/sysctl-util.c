/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "af-list.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "parse-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "string-util.h"
#include "sysctl-util.h"

char* sysctl_normalize(char *s) {
        char *n;

        n = strpbrk(s, "/.");

        /* If the first separator is a slash, the path is
         * assumed to be normalized and slashes remain slashes
         * and dots remains dots. */

        if (n && *n == '.')
                /* Dots become slashes and slashes become dots. Fun. */
                do {
                        if (*n == '.')
                                *n = '/';
                        else
                                *n = '.';

                        n = strpbrk(n + 1, "/.");
                } while (n);

        path_simplify(s);

        /* Kill the leading slash, but keep the first character of the string in the same place. */
        if (s[0] == '/' && s[1] != 0)
                memmove(s, s+1, strlen(s));

        return s;
}

static int shadow_update(Hashmap **shadow, const char *property, const char *value) {
        _cleanup_free_ char *k = NULL, *v = NULL, *cur_k = NULL, *cur_v = NULL;
        int r;

        assert(property);
        assert(value);

        if (!shadow)
                return 0;

        k = strdup(property);
        if (!k)
                return -ENOMEM;

        v = strdup(value);
        if (!v)
                return -ENOMEM;

        cur_v = hashmap_remove2(*shadow, k, (void**)&cur_k);

        r = hashmap_ensure_put(shadow, &path_hash_ops_free_free, k, v);
        if (r < 0) {
                assert(r != -EEXIST);

                return r;
        }

        TAKE_PTR(k);
        TAKE_PTR(v);

        return 0;
}

int sysctl_write_full(const char *property, const char *value, Hashmap **shadow) {
        char *p;
        int r;

        assert(property);
        assert(value);

        p = strjoina("/proc/sys/", property);

        path_simplify(p);
        if (!path_is_normalized(p))
                return -EINVAL;

        log_debug("Setting '%s' to '%s'", p, value);

        r = shadow_update(shadow, p, value);
        if (r < 0)
                return r;

        return write_string_file(p, value, WRITE_STRING_FILE_VERIFY_ON_FAILURE | WRITE_STRING_FILE_DISABLE_BUFFER | WRITE_STRING_FILE_SUPPRESS_REDUNDANT_VIRTUAL);
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

static const char* af_to_sysctl_dir(int af) {
        if (af == AF_MPLS)
                return "mpls";

        return af_to_ipv4_ipv6(af);
}

int sysctl_write_ip_property(int af, const char *ifname, const char *property, const char *value, Hashmap **shadow) {
        const char *p;

        assert(property);
        assert(value);

        if (!IN_SET(af, AF_INET, AF_INET6, AF_MPLS))
                return -EAFNOSUPPORT;

        if (ifname) {
                if (!ifname_valid_full(ifname, IFNAME_VALID_SPECIAL))
                        return -EINVAL;

                p = strjoina("net/", af_to_sysctl_dir(af), "/conf/", ifname, "/", property);
        } else
                p = strjoina("net/", af_to_sysctl_dir(af), "/", property);

        return sysctl_write_full(p, value, shadow);
}

int sysctl_write_ip_neighbor_property(int af, const char *ifname, const char *property, const char *value, Hashmap **shadow) {
        const char *p;

        assert(property);
        assert(value);
        assert(ifname);

        if (!IN_SET(af, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        if (ifname) {
                if (!ifname_valid_full(ifname, IFNAME_VALID_SPECIAL))
                        return -EINVAL;
                p = strjoina("net/", af_to_ipv4_ipv6(af), "/neigh/", ifname, "/", property);
        } else
                p = strjoina("net/", af_to_ipv4_ipv6(af), "/neigh/default/", property);

        return sysctl_write_full(p, value, shadow);
}

int sysctl_read(const char *property, char **ret) {
        char *p;
        int r;

        assert(property);

        p = strjoina("/proc/sys/", property);

        path_simplify(p);
        if (!path_is_normalized(p)) /* Filter out attempts to write to /proc/sys/../../…, just in case */
                return -EINVAL;

        r = read_full_virtual_file(p, ret, NULL);
        if (r < 0)
                return r;
        if (ret)
                delete_trailing_chars(*ret, NEWLINE);

        return r;
}

int sysctl_read_ip_property(int af, const char *ifname, const char *property, char **ret) {
        const char *p;

        assert(property);

        if (!IN_SET(af, AF_INET, AF_INET6, AF_MPLS))
                return -EAFNOSUPPORT;

        if (ifname) {
                if (!ifname_valid_full(ifname, IFNAME_VALID_SPECIAL))
                        return -EINVAL;

                p = strjoina("net/", af_to_sysctl_dir(af), "/conf/", ifname, "/", property);
        } else
                p = strjoina("net/", af_to_sysctl_dir(af), "/", property);

        return sysctl_read(p, ret);
}

int sysctl_read_ip_property_int(int af, const char *ifname, const char *property, int *ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);

        r = sysctl_read_ip_property(af, ifname, property, &s);
        if (r < 0)
                return r;

        return safe_atoi(s, ret);
}

int sysctl_read_ip_property_uint32(int af, const char *ifname, const char *property, uint32_t *ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(ret);

        r = sysctl_read_ip_property(af, ifname, property, &s);
        if (r < 0)
                return r;

        return safe_atou32(s, ret);
}
