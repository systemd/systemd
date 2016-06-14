/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <dlfcn.h>
#include <stdlib.h>
#include <net/if.h>

#include "log.h"
#include "nss-util.h"
#include "path-util.h"
#include "string-util.h"
#include "alloc-util.h"
#include "in-addr-util.h"
#include "hexdecoct.h"
#include "af-list.h"
#include "stdio-util.h"
#include "strv.h"
#include "errno-list.h"
#include "hostname-util.h"
#include "local-addresses.h"

static const char* nss_status_to_string(enum nss_status status, char *buf, size_t buf_len) {
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
                snprintf(buf, buf_len, "%i", status);
                return buf;
        }
};

static const char* af_to_string(int family, char *buf, size_t buf_len) {
        const char *name;

        if (family == AF_UNSPEC)
                return "*";

        name = af_to_name(family);
        if (name)
                return name;

        snprintf(buf, buf_len, "%i", family);
        return buf;
}

static void* open_handle(const char* dir, const char* module, int flags) {
        const char *path;
        void *handle;

        if (dir)
                path = strjoina(dir, "/.libs/libnss_", module, ".so.2");
        else
                path = strjoina("libnss_", module, ".so.2");

        handle = dlopen(path, flags);
        assert_se(handle);
        return handle;
}

static int print_gaih_addrtuples(const struct gaih_addrtuple *tuples) {
        const struct gaih_addrtuple *it;
        int n = 0;

        for (it = tuples; it; it = it->next) {
                _cleanup_free_ char *a = NULL;
                union in_addr_union u;
                int r;
                char family_name[DECIMAL_STR_MAX(int)];
                char ifname[IF_NAMESIZE];

                memcpy(&u, it->addr, 16);
                r = in_addr_to_string(it->family, &u, &a);
                assert_se(r == 0 || r == -EAFNOSUPPORT);
                if (r == -EAFNOSUPPORT)
                        assert_se((a = hexmem(it->addr, 16)));

                if (it->scopeid == 0)
                        goto numerical_index;

                if (if_indextoname(it->scopeid, ifname) == NULL) {
                        log_warning("if_indextoname(%d) failed: %m", it->scopeid);
                numerical_index:
                        xsprintf(ifname, "%i", it->scopeid);
                };

                log_info("        \"%s\" %s %s %%%s",
                         it->name,
                         af_to_string(it->family, family_name, sizeof family_name),
                         a,
                         ifname);
                n ++;
        }
        return n;
}

static void print_struct_hostent(struct hostent *host, const char *canon) {
        char **s;

        log_info("        \"%s\"", host->h_name);
        STRV_FOREACH(s, host->h_aliases)
                log_info("        alias \"%s\"", *s);
        STRV_FOREACH(s, host->h_addr_list) {
                union in_addr_union u;
                _cleanup_free_ char *a = NULL;
                char family_name[DECIMAL_STR_MAX(int)];
                int r;

                assert_se((unsigned) host->h_length == FAMILY_ADDRESS_SIZE(host->h_addrtype));
                memcpy(&u, *s, host->h_length);
                r = in_addr_to_string(host->h_addrtype, &u, &a);
                assert_se(r == 0);
                log_info("        %s %s",
                         af_to_string(host->h_addrtype, family_name, sizeof family_name),
                         a);
        }
        if (canon)
                log_info("        canonical: \"%s\"", canon);
}

static void test_gethostbyname4_r(void *handle, const char *module, const char *name) {
        const char *fname;
        _nss_gethostbyname4_r_t f;
        char buffer[2000];
        struct gaih_addrtuple *pat = NULL;
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        int32_t ttl = INT32_MAX; /* nss-dns wants to return the lowest ttl,
                                    and will access this variable through *ttlp,
                                    so we need to set it to something.
                                    I'm not sure if this is a bug in nss-dns
                                    or not. */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        int n;

        fname = strjoina("_nss_", module, "_gethostbyname4_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        assert_se(f);

        status = f(name, &pat, buffer, sizeof buffer, &errno1, &errno2, &ttl);
        if (status == NSS_STATUS_SUCCESS) {
                log_info("%s(\"%s\") → status=%s%-20spat=buffer+0x%tx errno=%d/%s h_errno=%d/%s ttl=%"PRIi32,
                         fname, name,
                         nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                         pat ? (char*) pat - buffer : 0,
                         errno1, errno_to_name(errno1) ?: "---",
                         errno2, hstrerror(errno2),
                         ttl);
                n = print_gaih_addrtuples(pat);
        } else {
                log_info("%s(\"%s\") → status=%s%-20spat=0x%p errno=%d/%s h_errno=%d/%s",
                         fname, name,
                         nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                         pat,
                         errno1, errno_to_name(errno1) ?: "---",
                         errno2, hstrerror(errno2));
                n = 0;
        }

        if (STR_IN_SET(module, "resolve", "mymachines") && status == NSS_STATUS_UNAVAIL)
                return;

        if (STR_IN_SET(module, "myhostname", "resolve") && streq(name, "localhost")) {
                assert_se(status == NSS_STATUS_SUCCESS);
                assert_se(n == 2);
        }
}


static void test_gethostbyname3_r(void *handle, const char *module, const char *name, int af) {
        const char *fname;
        _nss_gethostbyname3_r_t f;
        char buffer[2000];
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        int32_t ttl = INT32_MAX; /* nss-dns wants to return the lowest ttl,
                                    and will access this variable through *ttlp,
                                    so we need to set it to something.
                                    I'm not sure if this is a bug in nss-dns
                                    or not. */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct hostent host;
        char *canon;
        char family_name[DECIMAL_STR_MAX(int)];

        fname = strjoina("_nss_", module, "_gethostbyname3_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        assert_se(f);

        status = f(name, af, &host, buffer, sizeof buffer, &errno1, &errno2, &ttl, &canon);
        log_info("%s(\"%s\", %s) → status=%s%-20serrno=%d/%s h_errno=%d/%s ttl=%"PRIi32,
                 fname, name, af_to_string(af, family_name, sizeof family_name),
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---",
                 errno2, hstrerror(errno2),
                 ttl);
        if (status == NSS_STATUS_SUCCESS)
                print_struct_hostent(&host, canon);
}

static void test_gethostbyname2_r(void *handle, const char *module, const char *name, int af) {
        const char *fname;
        _nss_gethostbyname2_r_t f;
        char buffer[2000];
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct hostent host;
        char family_name[DECIMAL_STR_MAX(int)];

        fname = strjoina("_nss_", module, "_gethostbyname2_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        assert_se(f);

        status = f(name, af, &host, buffer, sizeof buffer, &errno1, &errno2);
        log_info("%s(\"%s\", %s) → status=%s%-20serrno=%d/%s h_errno=%d/%s",
                 fname, name, af_to_string(af, family_name, sizeof family_name),
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---",
                 errno2, hstrerror(errno2));
        if (status == NSS_STATUS_SUCCESS)
                print_struct_hostent(&host, NULL);
}

static void test_gethostbyname_r(void *handle, const char *module, const char *name) {
        const char *fname;
        _nss_gethostbyname_r_t f;
        char buffer[2000];
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct hostent host;

        fname = strjoina("_nss_", module, "_gethostbyname_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        assert_se(f);

        status = f(name, &host, buffer, sizeof buffer, &errno1, &errno2);
        log_info("%s(\"%s\") → status=%s%-20serrno=%d/%s h_errno=%d/%s",
                 fname, name,
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---",
                 errno2, hstrerror(errno2));
        if (status == NSS_STATUS_SUCCESS)
                print_struct_hostent(&host, NULL);
}

static void test_gethostbyaddr2_r(void *handle,
                                  const char *module,
                                  const void* addr, socklen_t len,
                                  int af) {

        const char *fname;
        _nss_gethostbyaddr2_r_t f;
        char buffer[2000];
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct hostent host;
        int32_t ttl = INT32_MAX;
        _cleanup_free_ char *addr_pretty = NULL;

        fname = strjoina("_nss_", module, "_gethostbyaddr2_r");
        f = dlsym(handle, fname);

        log_full_errno(f ? LOG_DEBUG : LOG_INFO,  errno,
                       "dlsym(0x%p, %s) → 0x%p: %m", handle, fname, f);
        if (!f)
                return;

        assert_se(in_addr_to_string(af, addr, &addr_pretty) >= 0);

        status = f(addr, len, af, &host, buffer, sizeof buffer, &errno1, &errno2, &ttl);
        log_info("%s(\"%s\") → status=%s%-20serrno=%d/%s h_errno=%d/%s ttl=%"PRIi32,
                 fname, addr_pretty,
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---",
                 errno2, hstrerror(errno2),
                 ttl);
        if (status == NSS_STATUS_SUCCESS)
                print_struct_hostent(&host, NULL);
}

static void test_gethostbyaddr_r(void *handle,
                                 const char *module,
                                 const void* addr, socklen_t len,
                                 int af) {

        const char *fname;
        _nss_gethostbyaddr_r_t f;
        char buffer[2000];
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct hostent host;
        _cleanup_free_ char *addr_pretty = NULL;

        fname = strjoina("_nss_", module, "_gethostbyaddr_r");
        f = dlsym(handle, fname);

        log_full_errno(f ? LOG_DEBUG : LOG_INFO,  errno,
                       "dlsym(0x%p, %s) → 0x%p: %m", handle, fname, f);
        if (!f)
                return;

        assert_se(in_addr_to_string(af, addr, &addr_pretty) >= 0);

        status = f(addr, len, af, &host, buffer, sizeof buffer, &errno1, &errno2);
        log_info("%s(\"%s\") → status=%s%-20serrno=%d/%s h_errno=%d/%s",
                 fname, addr_pretty,
                 nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                 errno1, errno_to_name(errno1) ?: "---",
                 errno2, hstrerror(errno2));
        if (status == NSS_STATUS_SUCCESS)
                print_struct_hostent(&host, NULL);
}

static void test_byname(void *handle, const char *module, const char *name) {
        test_gethostbyname4_r(handle, module, name);
        puts("");

        test_gethostbyname3_r(handle, module, name, AF_INET);
        puts("");
        test_gethostbyname3_r(handle, module, name, AF_INET6);
        puts("");
        test_gethostbyname3_r(handle, module, name, AF_UNSPEC);
        puts("");
        test_gethostbyname3_r(handle, module, name, AF_LOCAL);
        puts("");

        test_gethostbyname2_r(handle, module, name, AF_INET);
        puts("");
        test_gethostbyname2_r(handle, module, name, AF_INET6);
        puts("");
        test_gethostbyname2_r(handle, module, name, AF_UNSPEC);
        puts("");
        test_gethostbyname2_r(handle, module, name, AF_LOCAL);
        puts("");

        test_gethostbyname_r(handle, module, name);
        puts("");
}

static void test_byaddr(void *handle,
                        const char *module,
                        const void* addr, socklen_t len,
                        int af) {
        test_gethostbyaddr2_r(handle, module, addr, len, af);
        puts("");

        test_gethostbyaddr_r(handle, module, addr, len, af);
        puts("");
}

#ifdef HAVE_MYHOSTNAME
#  define MODULE1 "myhostname\0"
#else
#  define MODULE1
#endif
#ifdef HAVE_RESOLVED
#  define MODULE2 "resolve\0"
#else
#  define MODULE2
#endif
#ifdef HAVE_MACHINED
#  define MODULE3 "mymachines\0"
#else
#  define MODULE3
#endif
#define MODULE4 "dns\0"

int main(int argc, char **argv) {
        _cleanup_free_ char *dir = NULL, *hostname = NULL;
        const char *module;

        const uint32_t local_address_ipv4 = htobe32(0x7F000001);
        const uint32_t local_address_ipv4_2 = htobe32(0x7F000002);
        _cleanup_free_ struct local_address *addresses = NULL;
        int n_addresses;

        log_set_max_level(LOG_INFO);
        log_parse_environment();

        dir = dirname_malloc(argv[0]);
        assert_se(dir);

        hostname = gethostname_malloc();
        assert_se(hostname);

        n_addresses = local_addresses(NULL, 0, AF_UNSPEC, &addresses);
        if (n_addresses < 0) {
                log_info_errno(n_addresses, "Failed to query local addresses: %m");
                n_addresses = 0;
        }

        NULSTR_FOREACH(module, MODULE1 MODULE2 MODULE3 MODULE4) {
                void *handle;
                const char *name;
                int i;

                log_info("======== %s ========", module);

                handle = open_handle(streq(module, "dns") ? NULL : dir,
                                     module,
                                     RTLD_LAZY|RTLD_NODELETE);
                NULSTR_FOREACH(name, "localhost\0" "gateway\0" "foo_no_such_host\0")
                        test_byname(handle, module, name);

                test_byname(handle, module, hostname);

                test_byaddr(handle, module, &local_address_ipv4, sizeof local_address_ipv4, AF_INET);
                test_byaddr(handle, module, &local_address_ipv4_2, sizeof local_address_ipv4_2, AF_INET);
                test_byaddr(handle, module, &in6addr_loopback, sizeof in6addr_loopback, AF_INET6);

                for (i = 0; i < n_addresses; i++)
                        test_byaddr(handle, module,
                                    &addresses[i].address,
                                    FAMILY_ADDRESS_SIZE(addresses[i].family),
                                    addresses[i].family);

                dlclose(handle);

                log_info(" ");
        }

        return EXIT_SUCCESS;
}
