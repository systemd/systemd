/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "bus-message-util.h"
#include "bus-util.h"
#include "copy.h"
#include "resolve-util.h"

int bus_message_read_id128(sd_bus_message *m, sd_id128_t *ret) {
        const void *a;
        size_t sz;
        int r;

        assert(m);

        r = sd_bus_message_read_array(m, 'y', &a, &sz);
        if (r < 0)
                return r;

        switch (sz) {

        case 0:
                if (ret)
                        *ret = SD_ID128_NULL;
                return 0;

        case sizeof(sd_id128_t):
                if (ret)
                        memcpy(ret, a, sz);
                return !memeqzero(a, sz); /* This mimics sd_id128_is_null(), but ret may be NULL,
                                           * and a may be misaligned, so use memeqzero() here. */

        default:
                return -EINVAL;
        }
}

int bus_message_read_ifindex(sd_bus_message *message, sd_bus_error *error, int *ret) {
        int ifindex, r;

        assert(message);
        assert(ret);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "i", &ifindex);
        if (r < 0)
                return r;

        if (ifindex <= 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid interface index");

        *ret = ifindex;

        return 0;
}

int bus_message_read_family(sd_bus_message *message, sd_bus_error *error, int *ret) {
        int family, r;

        assert(message);
        assert(ret);

        assert_cc(sizeof(int) == sizeof(int32_t));

        r = sd_bus_message_read(message, "i", &family);
        if (r < 0)
                return r;

        if (!IN_SET(family, AF_INET, AF_INET6))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

        *ret = family;
        return 0;
}

int bus_message_read_in_addr_auto(sd_bus_message *message, sd_bus_error *error, int *ret_family, union in_addr_union *ret_addr) {
        int family, r;
        const void *d;
        size_t sz;

        assert(message);

        r = sd_bus_message_read(message, "i", &family);
        if (r < 0)
                return r;

        r = sd_bus_message_read_array(message, 'y', &d, &sz);
        if (r < 0)
                return r;

        if (!IN_SET(family, AF_INET, AF_INET6))
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Unknown address family %i", family);

        if (sz != FAMILY_ADDRESS_SIZE(family))
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid address size");

        if (ret_family)
                *ret_family = family;
        if (ret_addr)
                memcpy(ret_addr, d, sz);
        return 0;
}

static int bus_message_read_dns_one(
                        sd_bus_message *message,
                        sd_bus_error *error,
                        bool extended,
                        int *ret_family,
                        union in_addr_union *ret_address,
                        uint16_t *ret_port,
                        const char **ret_server_name) {
        const char *server_name = NULL;
        union in_addr_union a;
        uint16_t port = 0;
        int family, r;

        assert(message);
        assert(ret_family);
        assert(ret_address);
        assert(ret_port);
        assert(ret_server_name);

        r = sd_bus_message_enter_container(message, 'r', extended ? "iayqs" : "iay");
        if (r <= 0)
                return r;

        r = bus_message_read_in_addr_auto(message, error, &family, &a);
        if (r < 0)
                return r;

        if (!dns_server_address_valid(family, &a)) {
                r = sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid DNS server address");
                assert(r < 0);
                return r;
        }

        if (extended) {
                r = sd_bus_message_read(message, "q", &port);
                if (r < 0)
                        return r;

                if (IN_SET(port, 53, 853))
                        port = 0;

                r = sd_bus_message_read(message, "s", &server_name);
                if (r < 0)
                        return r;
        }

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        *ret_family = family;
        *ret_address = a;
        *ret_port = port;
        *ret_server_name = server_name;

        return 1;
}

int bus_message_read_dns_servers(
                        sd_bus_message *message,
                        sd_bus_error *error,
                        bool extended,
                        struct in_addr_full ***ret_dns,
                        size_t *ret_n_dns) {

        struct in_addr_full **dns = NULL;
        size_t n = 0;
        int r;

        assert(message);
        assert(ret_dns);
        assert(ret_n_dns);

        r = sd_bus_message_enter_container(message, 'a', extended ? "(iayqs)" : "(iay)");
        if (r < 0)
                return r;

        for (;;) {
                const char *server_name;
                union in_addr_union a;
                uint16_t port;
                int family;

                r = bus_message_read_dns_one(message, error, extended, &family, &a, &port, &server_name);
                if (r < 0)
                        goto clear;
                if (r == 0)
                        break;

                if (!GREEDY_REALLOC(dns, n+1)) {
                        r = -ENOMEM;
                        goto clear;
                }

                r = in_addr_full_new(family, &a, port, 0, server_name, dns + n);
                if (r < 0)
                        goto clear;

                n++;
        }

        *ret_dns = TAKE_PTR(dns);
        *ret_n_dns = n;
        return 0;

clear:
        for (size_t i = 0; i < n; i++)
                in_addr_full_free(dns[i]);
        free(dns);

        return r;
}

int bus_message_append_string_set(sd_bus_message *m, const Set *set) {
        int r;

        assert(m);

        r = sd_bus_message_open_container(m, 'a', "s");
        if (r < 0)
                return r;

        const char *s;
        SET_FOREACH(s, set) {
                r = sd_bus_message_append(m, "s", s);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(m);
}

int bus_message_dump_string(sd_bus_message *message) {
        const char *s;
        int r;

        assert(message);

        r = sd_bus_message_read(message, "s", &s);
        if (r < 0)
                return bus_log_parse_error(r);

        fputs(s, stdout);
        return 0;
}

int bus_message_dump_fd(sd_bus_message *message) {
        int fd, r;

        assert(message);

        r = sd_bus_message_read(message, "h", &fd);
        if (r < 0)
                return bus_log_parse_error(r);

        fflush(stdout);
        r = copy_bytes(fd, STDOUT_FILENO, UINT64_MAX, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to dump contents in received file descriptor: %m");

        return 0;
}

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(bus_message_hash_ops,
                                      void, trivial_hash_func, trivial_compare_func,
                                      sd_bus_message, sd_bus_message_unref);
