/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <poll.h>
#include <sys/inotify.h>

#include "sd-network.h"

#include "alloc-util.h"
#include "env-file.h"
#include "fd-util.h"
#include "fs-util.h"
#include "macro.h"
#include "parse-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"

static int network_get_string(const char *field, const char *network_namespace, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(ret, -EINVAL);

        if (network_namespace) {
                p = strjoin("/run/systemd/netif.", network_namespace, "/state");
                if (!p)
                        return -ENOMEM;
        }

        r = parse_env_file(NULL, p ?: "/run/systemd/netif/state", field, &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *ret = TAKE_PTR(s);

        return 0;
}

_public_ int sd_network_get_operational_state(const char *network_namespace, char **state) {
        return network_get_string("OPER_STATE", network_namespace, state);
}

_public_ int sd_network_get_carrier_state(const char *network_namespace, char **state) {
        return network_get_string("CARRIER_STATE", network_namespace, state);
}

_public_ int sd_network_get_address_state(const char *network_namespace, char **state) {
        return network_get_string("ADDRESS_STATE", network_namespace, state);
}

static int network_get_strv(const char *key, const char *network_namespace, char ***ret) {
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(ret, -EINVAL);

        if (network_namespace) {
                p = strjoin("/run/systemd/netif.", network_namespace, "/state");
                if (!p)
                        return -ENOMEM;
        }

        r = parse_env_file(NULL, p ?: "/run/systemd/netif/state", key, &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        a = strv_split(s, " ");
        if (!a)
                return -ENOMEM;

        strv_uniq(a);
        r = (int) strv_length(a);

        *ret = TAKE_PTR(a);

        return r;
}

_public_ int sd_network_get_dns(const char *network_namespace, char ***ret) {
        return network_get_strv("DNS", network_namespace, ret);
}

_public_ int sd_network_get_ntp(const char *network_namespace, char ***ret) {
        return network_get_strv("NTP", network_namespace, ret);
}

_public_ int sd_network_get_search_domains(const char *network_namespace, char ***ret) {
        return network_get_strv("DOMAINS", network_namespace, ret);
}

_public_ int sd_network_get_route_domains(const char *network_namespace, char ***ret) {
        return network_get_strv("ROUTE_DOMAINS", network_namespace, ret);
}

static int network_link_get_string(int ifindex, const char *field, const char *network_namespace, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        if (network_namespace)
                r = asprintf(&p, "/run/systemd/netif.%s/links/%i", network_namespace, ifindex);
        else
                r = asprintf(&p, "/run/systemd/netif/links/%i", ifindex);
        if (r < 0)
                return -ENOMEM;

        r = parse_env_file(NULL, p, field, &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *ret = TAKE_PTR(s);

        return 0;
}

static int network_link_get_strv(int ifindex, const char *key, const char *network_namespace, char ***ret) {
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        if (network_namespace)
                r = asprintf(&p, "/run/systemd/netif.%s/links/%i", network_namespace, ifindex);
        else
                r = asprintf(&p, "/run/systemd/netif/links/%i", ifindex);
        if (r < 0)
                return -ENOMEM;

        r = parse_env_file(NULL, p, key, &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        a = strv_split(s, " ");
        if (!a)
                return -ENOMEM;

        strv_uniq(a);
        r = (int) strv_length(a);

        *ret = TAKE_PTR(a);

        return r;
}

_public_ int sd_network_link_get_setup_state(int ifindex, const char *network_namespace, char **state) {
        return network_link_get_string(ifindex, "ADMIN_STATE", network_namespace, state);
}

_public_ int sd_network_link_get_network_file(int ifindex, const char *network_namespace, char **filename) {
        return network_link_get_string(ifindex, "NETWORK_FILE", network_namespace, filename);
}

_public_ int sd_network_link_get_operational_state(int ifindex, const char *network_namespace, char **state) {
        return network_link_get_string(ifindex, "OPER_STATE", network_namespace, state);
}

_public_ int sd_network_link_get_carrier_state(int ifindex, const char *network_namespace, char **state) {
        return network_link_get_string(ifindex, "CARRIER_STATE", network_namespace, state);
}

_public_ int sd_network_link_get_address_state(int ifindex, const char *network_namespace, char **state) {
        return network_link_get_string(ifindex, "ADDRESS_STATE", network_namespace, state);
}

_public_ int sd_network_link_get_required_for_online(int ifindex, const char *network_namespace) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = network_link_get_string(ifindex, "REQUIRED_FOR_ONLINE", network_namespace, &s);
        if (r < 0) {
                /* Handle -ENODATA as RequiredForOnline=yes, for compatibility */
                if (r == -ENODATA)
                        return true;
                return r;
        }

        return parse_boolean(s);
}

_public_ int sd_network_link_get_required_operstate_for_online(int ifindex, const char *network_namespace, char **state) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert_return(state, -EINVAL);

        r = network_link_get_string(ifindex, "REQUIRED_OPER_STATE_FOR_ONLINE", network_namespace, &s);
        if (r < 0) {
                if (r != -ENODATA)
                        return r;

                /* For compatibility, assuming degraded. */
                s = strdup("degraded");
                if (!s)
                        return -ENOMEM;
        }

        *state = TAKE_PTR(s);
        return 0;
}

_public_ int sd_network_link_get_llmnr(int ifindex, const char *network_namespace, char **llmnr) {
        return network_link_get_string(ifindex, "LLMNR", network_namespace, llmnr);
}

_public_ int sd_network_link_get_mdns(int ifindex, const char *network_namespace, char **mdns) {
        return network_link_get_string(ifindex, "MDNS", network_namespace, mdns);
}

_public_ int sd_network_link_get_dns_over_tls(int ifindex, const char *network_namespace, char **dns_over_tls) {
        return network_link_get_string(ifindex, "DNS_OVER_TLS", network_namespace, dns_over_tls);
}

_public_ int sd_network_link_get_dnssec(int ifindex, const char *network_namespace, char **dnssec) {
        return network_link_get_string(ifindex, "DNSSEC", network_namespace, dnssec);
}

_public_ int sd_network_link_get_dnssec_negative_trust_anchors(int ifindex, const char *network_namespace, char ***nta) {
        return network_link_get_strv(ifindex, "DNSSEC_NTA", network_namespace, nta);
}

_public_ int sd_network_link_get_timezone(int ifindex, const char *network_namespace, char **ret) {
        return network_link_get_string(ifindex, "TIMEZONE", network_namespace, ret);
}

_public_ int sd_network_link_get_dhcp4_address(int ifindex, const char *network_namespace, char **ret) {
        return network_link_get_string(ifindex, "DHCP4_ADDRESS", network_namespace, ret);
}

_public_ int sd_network_link_get_dns(int ifindex, const char *network_namespace, char ***ret) {
        return network_link_get_strv(ifindex, "DNS", network_namespace, ret);
}

_public_ int sd_network_link_get_ntp(int ifindex, const char *network_namespace, char ***ret) {
        return network_link_get_strv(ifindex, "NTP", network_namespace, ret);
}

_public_ int sd_network_link_get_search_domains(int ifindex, const char *network_namespace, char ***ret) {
        return network_link_get_strv(ifindex, "DOMAINS", network_namespace, ret);
}

_public_ int sd_network_link_get_route_domains(int ifindex, const char *network_namespace, char ***ret) {
        return network_link_get_strv(ifindex, "ROUTE_DOMAINS", network_namespace, ret);
}

_public_ int sd_network_link_get_sip_servers(int ifindex, const char *network_namespace, char ***ret) {
        return network_link_get_strv(ifindex, "SIP", network_namespace, ret);
}

_public_ int sd_network_link_get_dns_default_route(int ifindex, const char *network_namespace) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        int r;

        assert_return(ifindex > 0, -EINVAL);

        if (network_namespace)
                r = asprintf(&p, "/run/systemd/netif.%s/links/%i", network_namespace, ifindex);
        else
                r = asprintf(&p, "/run/systemd/netif/links/%i", ifindex);
        if (r < 0)
                return -ENOMEM;

        r = parse_env_file(NULL, p, "DNS_DEFAULT_ROUTE", &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;
        return parse_boolean(s);
}

static int network_link_get_ifindexes(int ifindex, const char *key, const char *network_namespace, int **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL;
        _cleanup_free_ int *ifis = NULL;
        size_t allocated = 0, c = 0;
        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        if (network_namespace)
                r = asprintf(&p, "/run/systemd/netif.%s/links/%i", network_namespace, ifindex);
        else
                r = asprintf(&p, "/run/systemd/netif/links/%i", ifindex);
        if (r < 0)
                return -ENOMEM;

        r = parse_env_file(NULL, p, key, &s);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        for (const char *x = s;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&x, &word, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!GREEDY_REALLOC(ifis, allocated, c + 2))
                        return -ENOMEM;

                r = ifis[c++] = parse_ifindex(word);
                if (r < 0)
                        return r;
        }

        if (ifis)
                ifis[c] = 0; /* Let's add a 0 ifindex to the end, to be nice */

        *ret = TAKE_PTR(ifis);

        return c;
}

_public_ int sd_network_link_get_carrier_bound_to(int ifindex, const char *network_namespace, int **ret) {
        return network_link_get_ifindexes(ifindex, "CARRIER_BOUND_TO", network_namespace, ret);
}

_public_ int sd_network_link_get_carrier_bound_by(int ifindex, const char *network_namespace, int **ret) {
        return network_link_get_ifindexes(ifindex, "CARRIER_BOUND_BY", network_namespace, ret);
}

static int MONITOR_TO_FD(sd_network_monitor *m) {
        return (int) (unsigned long) m - 1;
}

static sd_network_monitor* FD_TO_MONITOR(int fd) {
        return (sd_network_monitor*) (unsigned long) (fd + 1);
}

static int monitor_add_inotify_watch(int fd, const char *network_namespace) {
        _cleanup_free_ char *p = NULL;
        int k;

        if (network_namespace) {
                p = strjoin("/run/systemd/netif.", network_namespace, "/links/");
                if (!p)
                        return -ENOMEM;
        }

        k = inotify_add_watch(fd, p ?: "/run/systemd/netif/links/", IN_MOVED_TO|IN_DELETE);
        if (k >= 0)
                return 0;
        else if (errno != ENOENT)
                return -errno;

        p = mfree(p);
        if (network_namespace) {
                p = strjoin("/run/systemd/netif.", network_namespace, "/");
                if (!p)
                        return -ENOMEM;
        }

        k = inotify_add_watch(fd, p ?: "/run/systemd/netif/", IN_CREATE|IN_ISDIR);
        if (k >= 0)
                return 0;
        else if (errno != ENOENT)
                return -errno;

        k = inotify_add_watch(fd, "/run/systemd/", IN_CREATE|IN_ISDIR);
        if (k < 0)
                return -errno;

        return 0;
}

_public_ int sd_network_monitor_new(sd_network_monitor **m, const char *category, const char *network_namespace) {
        _cleanup_close_ int fd = -1;
        int k;
        bool good = false;

        assert_return(m, -EINVAL);

        fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!category || streq(category, "links")) {
                k = monitor_add_inotify_watch(fd, network_namespace);
                if (k < 0)
                        return k;

                good = true;
        }

        if (!good)
                return -EINVAL;

        *m = FD_TO_MONITOR(fd);
        fd = -1;

        return 0;
}

_public_ sd_network_monitor* sd_network_monitor_unref(sd_network_monitor *m) {
        int fd;

        if (m) {
                fd = MONITOR_TO_FD(m);
                close_nointr(fd);
        }

        return NULL;
}

_public_ int sd_network_monitor_flush(sd_network_monitor *m, const char *network_namespace) {
        union inotify_event_buffer buffer;
        struct inotify_event *e;
        ssize_t l;
        int fd, k;

        assert_return(m, -EINVAL);

        fd = MONITOR_TO_FD(m);

        l = read(fd, &buffer, sizeof(buffer));
        if (l < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0;

                return -errno;
        }

        FOREACH_INOTIFY_EVENT(e, buffer, l) {
                if (e->mask & IN_ISDIR) {
                        k = monitor_add_inotify_watch(fd, network_namespace);
                        if (k < 0)
                                return k;

                        k = inotify_rm_watch(fd, e->wd);
                        if (k < 0)
                                return -errno;
                }
        }

        return 0;
}

_public_ int sd_network_monitor_get_fd(sd_network_monitor *m) {

        assert_return(m, -EINVAL);

        return MONITOR_TO_FD(m);
}

_public_ int sd_network_monitor_get_events(sd_network_monitor *m) {

        assert_return(m, -EINVAL);

        /* For now we will only return POLLIN here, since we don't
         * need anything else ever for inotify.  However, let's have
         * this API to keep our options open should we later on need
         * it. */
        return POLLIN;
}

_public_ int sd_network_monitor_get_timeout(sd_network_monitor *m, uint64_t *timeout_usec) {

        assert_return(m, -EINVAL);
        assert_return(timeout_usec, -EINVAL);

        /* For now we will only return (uint64_t) -1, since we don't
         * need any timeout. However, let's have this API to keep our
         * options open should we later on need it. */
        *timeout_usec = (uint64_t) -1;
        return 0;
}
