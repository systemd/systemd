/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

#include "af-list.h"
#include "alloc-util.h"
#include "dlfcn-util.h"
#include "env-util.h"
#include "errno-list.h"
#include "format-ifname.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "log.h"
#include "main-func.h"
#include "nss-test-util.h"
#include "nss-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

static size_t arg_bufsize = 1024;

static const char* af_to_string(int family, char *buf, size_t buf_len) {
        const char *name;

        if (family == AF_UNSPEC)
                return "*";

        name = af_to_name(family);
        if (name)
                return name;

        (void) snprintf(buf, buf_len, "%i", family);
        return buf;
}

static int print_gaih_addrtuples(const struct gaih_addrtuple *tuples) {
        int r, n = 0;

        for (const struct gaih_addrtuple *it = tuples; it; it = it->next) {
                _cleanup_free_ char *a = NULL;
                union in_addr_union u;
                char family_name[DECIMAL_STR_MAX(int)];

                memcpy(&u, it->addr, 16);
                r = in_addr_to_string(it->family, &u, &a);
                assert_se(IN_SET(r, 0, -EAFNOSUPPORT));
                if (r == -EAFNOSUPPORT)
                        assert_se(a = hexmem(it->addr, 16));

                log_info("        \"%s\" %s %s %s",
                         it->name,
                         af_to_string(it->family, family_name, sizeof family_name),
                         a,
                         FORMAT_IFNAME_FULL(it->scopeid, FORMAT_IFNAME_IFINDEX_WITH_PERCENT));

                n++;
        }
        return n;
}

static void print_struct_hostent(struct hostent *host, const char *canon) {
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
        char buffer[arg_bufsize];
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
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

        status = f(name, &pat, buffer, sizeof buffer, &errno1, &errno2, &ttl);
        if (status == NSS_STATUS_SUCCESS) {
                log_info("%s(\"%s\") → status=%s%-20spat=buffer+0x%"PRIxPTR" errno=%d/%s h_errno=%d/%s ttl=%"PRIi32,
                         fname, name,
                         nss_status_to_string(status, pretty_status, sizeof pretty_status), "\n",
                         pat ? (uintptr_t) pat - (uintptr_t) buffer : 0,
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

        if (streq(name, "localhost")) {
                if (streq(module, "myhostname")) {
                        assert_se(status == NSS_STATUS_SUCCESS);
                        assert_se(n == socket_ipv6_is_enabled() + 1);

                } else if (streq(module, "resolve") && secure_getenv_bool("SYSTEMD_NSS_RESOLVE_SYNTHESIZE") != 0) {
                        assert_se(status == NSS_STATUS_SUCCESS);
                        if (socket_ipv6_is_enabled())
                                assert_se(n == 2);
                        else
                                assert_se(n <= 2); /* Even if IPv6 is disabled, /etc/hosts may contain ::1. */
                }
        }
}

static void test_gethostbyname3_r(void *handle, const char *module, const char *name, int af) {
        const char *fname;
        _nss_gethostbyname3_r_t f;
        char buffer[arg_bufsize];
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
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

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
        char buffer[arg_bufsize];
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct hostent host;
        char family_name[DECIMAL_STR_MAX(int)];

        fname = strjoina("_nss_", module, "_gethostbyname2_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

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
        char buffer[arg_bufsize];
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct hostent host;

        fname = strjoina("_nss_", module, "_gethostbyname_r");
        f = dlsym(handle, fname);
        log_debug("dlsym(0x%p, %s) → 0x%p", handle, fname, f);
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

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
        char buffer[arg_bufsize];
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
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

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
        char buffer[arg_bufsize];
        int errno1 = 999, errno2 = 999; /* nss-dns doesn't set those */
        enum nss_status status;
        char pretty_status[DECIMAL_STR_MAX(enum nss_status)];
        struct hostent host;
        _cleanup_free_ char *addr_pretty = NULL;

        fname = strjoina("_nss_", module, "_gethostbyaddr_r");
        f = dlsym(handle, fname);

        log_full_errno(f ? LOG_DEBUG : LOG_INFO,  errno,
                       "dlsym(0x%p, %s) → 0x%p: %m", handle, fname, f);
        if (!f) {
                log_info("%s not defined", fname);
                return;
        }

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
        test_gethostbyname3_r(handle, module, name, AF_UNIX);
        puts("");

        test_gethostbyname2_r(handle, module, name, AF_INET);
        puts("");
        test_gethostbyname2_r(handle, module, name, AF_INET6);
        puts("");
        test_gethostbyname2_r(handle, module, name, AF_UNSPEC);
        puts("");
        test_gethostbyname2_r(handle, module, name, AF_UNIX);
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
        _cleanup_free_ struct local_address *addrs = NULL;

        n = local_addresses(NULL, 0, AF_UNSPEC, &addrs);
        if (n < 0)
                log_info_errno(n, "Failed to query local addresses: %m");

        assert_se(GREEDY_REALLOC(addrs, n + 3));

        addrs[n++] = (struct local_address) { .family = AF_INET,
                                              .address.in = { htobe32(0x7F000001) } };
        addrs[n++] = (struct local_address) { .family = AF_INET,
                                              .address.in = { htobe32(0x7F000002) } };
        addrs[n++] = (struct local_address) { .family = AF_INET6,
                                              .address.in6 = in6addr_loopback };

        *addresses = TAKE_PTR(addrs);
        return n;
}

static int test_one_module(const char *dir,
                           const char *module,
                           char **names,
                           struct local_address *addresses,
                           int n_addresses) {

        log_info("======== %s ========", module);

        _cleanup_(dlclosep) void *handle = nss_open_handle(dir, module, RTLD_NOW|RTLD_NODELETE);
        if (!handle)
                return -EINVAL;

        STRV_FOREACH(name, names)
                test_byname(handle, module, *name);

        for (int i = 0; i < n_addresses; i++)
                test_byaddr(handle, module,
                            &addresses[i].address,
                            FAMILY_ADDRESS_SIZE(addresses[i].family),
                            addresses[i].family);

        log_info(" ");
        return 0;
}

static int parse_argv(int argc, char **argv,
                      char ***the_modules,
                      char ***the_names,
                      struct local_address **the_addresses, int *n_addresses) {

        _cleanup_strv_free_ char **modules = NULL, **names = NULL;
        _cleanup_free_ struct local_address *addrs = NULL;
        const char *p;
        int r, n = 0;

        p = getenv("SYSTEMD_TEST_NSS_BUFSIZE");
        if (p) {
                r = safe_atozu(p, &arg_bufsize);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse $SYSTEMD_TEST_NSS_BUFSIZE");
        }

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
                                NULL);
        assert_se(modules);

        if (argc > 2) {
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
                                assert_se(GREEDY_REALLOC0(addrs, n + 1));

                                addrs[n++] = (struct local_address) { .family = family,
                                                                      .address = address };
                        }
                }
        } else {
                _cleanup_free_ char *hostname = NULL;
                assert_se(hostname = gethostname_malloc());
                assert_se(names = strv_new("localhost",
                                           "_gateway",
                                           "_outbound",
                                           hostname,
                                           slow_tests_enabled() ? "foo_no_such_host" : NULL));

                n = make_addresses(&addrs);
                assert_se(n >= 0);
        }

        *the_modules = TAKE_PTR(modules);
        *the_names = TAKE_PTR(names);
        *the_addresses = TAKE_PTR(addrs);
        *n_addresses = n;
        return 0;
}

static int run(int argc, char **argv) {
        _cleanup_free_ char *dir = NULL;
        _cleanup_strv_free_ char **modules = NULL, **names = NULL;
        _cleanup_free_ struct local_address *addresses = NULL;
        int n_addresses = 0;
        int r;

        test_setup_logging(LOG_INFO);

        r = parse_argv(argc, argv, &modules, &names, &addresses, &n_addresses);
        if (r < 0)
                return log_error_errno(r, "Failed to parse arguments: %m");

        assert_se(path_extract_directory(argv[0], &dir) >= 0);

        STRV_FOREACH(module, modules) {
                r = test_one_module(dir, *module, names, addresses, n_addresses);
                if (r < 0)
                        return r;
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
