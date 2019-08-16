/* SPDX-License-Identifier: LGPL-2.1+ */

#include <dlfcn.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

#include "af-list.h"
#include "alloc-util.h"
#include "errno-list.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "log.h"
#include "main-func.h"
#include "nss-util.h"
#include "path-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

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
        const char *path = NULL;
        void *handle;

        if (dir)
                path = strjoina(dir, "/libnss_", module, ".so.2");
        if (!path || access(path, F_OK) < 0)
                path = strjoina("libnss_", module, ".so.2");

        handle = dlopen(path, flags);
        if (!handle)
                log_error("Failed to load module %s: %s", module, dlerror());
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
                char ifname[IF_NAMESIZE + 1];

                memcpy(&u, it->addr, 16);
                r = in_addr_to_string(it->family, &u, &a);
                assert_se(IN_SET(r, 0, -EAFNOSUPPORT));
                if (r == -EAFNOSUPPORT)
                        assert_se(a = hexmem(it->addr, 16));

                if (it->scopeid == 0)
                        goto numerical_index;

                if (!format_ifname(it->scopeid, ifname)) {
                        log_warning_errno(errno, "if_indextoname(%d) failed: %m", it->scopeid);
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

static int make_addresses(struct local_address **addresses) {
        int n;
        size_t n_alloc;
        _cleanup_free_ struct local_address *addrs = NULL;

        n = local_addresses(NULL, 0, AF_UNSPEC, &addrs);
        if (n < 0)
                log_info_errno(n, "Failed to query local addresses: %m");

        n_alloc = n; /* we _can_ do that */
        if (!GREEDY_REALLOC(addrs, n_alloc, n + 3))
                return log_oom();

        addrs[n++] = (struct local_address) { .family = AF_INET,
                                              .address.in = { htobe32(0x7F000001) } };
        addrs[n++] = (struct local_address) { .family = AF_INET,
                                              .address.in = { htobe32(0x7F000002) } };
        addrs[n++] = (struct local_address) { .family = AF_INET6,
                                              .address.in6 = in6addr_loopback };
        return 0;
}

static int test_one_module(const char* dir,
                           const char *module,
                           char **names,
                           struct local_address *addresses,
                           int n_addresses) {
        void *handle;
        char **name;
        int i;

        log_info("======== %s ========", module);

        handle = open_handle(dir, module, RTLD_LAZY|RTLD_NODELETE);
        if (!handle)
                return -EINVAL;

        STRV_FOREACH(name, names)
                test_byname(handle, module, *name);

        for (i = 0; i < n_addresses; i++)
                test_byaddr(handle, module,
                            &addresses[i].address,
                            FAMILY_ADDRESS_SIZE(addresses[i].family),
                            addresses[i].family);

        log_info(" ");
        dlclose(handle);
        return 0;
}

static int parse_argv(int argc, char **argv,
                      char ***the_modules,
                      char ***the_names,
                      struct local_address **the_addresses, int *n_addresses) {

        int r, n = 0;
        _cleanup_strv_free_ char **modules = NULL, **names = NULL;
        _cleanup_free_ struct local_address *addrs = NULL;
        size_t n_allocated = 0;

        if (argc > 1)
                modules = strv_new(argv[1]);
        else
                modules = strv_new(
#if ENABLE_NSS_MYHOSTNAME
                                "myhostname",
#endif
#if ENABLE_NSS_RESOLVE
                                "resolve",
#endif
#if ENABLE_NSS_MYMACHINES
                                "mymachines",
#endif
                                "dns");
        if (!modules)
                return -ENOMEM;

        if (argc > 2) {
                char **name;
                int family;
                union in_addr_union address;

                STRV_FOREACH(name, argv + 2) {
                        r = in_addr_from_string_auto(*name, &family, &address);
                        if (r < 0) {
                                /* assume this is a name */
                                r = strv_extend(&names, *name);
                                if (r < 0)
                                        return r;
                        } else {
                                if (!GREEDY_REALLOC0(addrs, n_allocated, n + 1))
                                        return -ENOMEM;

                                addrs[n++] = (struct local_address) { .family = family,
                                                                      .address = address };
                        }
                }
        } else {
                _cleanup_free_ char *hostname;

                hostname = gethostname_malloc();
                if (!hostname)
                        return -ENOMEM;

                names = strv_new("localhost", "_gateway", "foo_no_such_host", hostname);
                if (!names)
                        return -ENOMEM;

                n = make_addresses(&addrs);
                if (n < 0)
                        return n;
        }

        *the_modules = modules;
        *the_names = names;
        modules = names = NULL;
        *the_addresses = addrs;
        *n_addresses = n;
        addrs = NULL;
        return 0;
}

static int run(int argc, char **argv) {
        _cleanup_free_ char *dir = NULL;
        _cleanup_strv_free_ char **modules = NULL, **names = NULL;
        _cleanup_free_ struct local_address *addresses = NULL;
        int n_addresses = 0;
        char **module;
        int r;

        test_setup_logging(LOG_INFO);

        r = parse_argv(argc, argv, &modules, &names, &addresses, &n_addresses);
        if (r < 0) {
                log_error_errno(r, "Failed to parse arguments: %m");
                return EXIT_FAILURE;
        }

        dir = dirname_malloc(argv[0]);
        if (!dir)
                return log_oom();

        STRV_FOREACH(module, modules) {
                r = test_one_module(dir, *module, names, addresses, n_addresses);
                if (r < 0)
                        return r;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
