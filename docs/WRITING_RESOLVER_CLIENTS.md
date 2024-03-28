---
title: Writing Resolver Clients
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Writing Resolver Clients

_Or: How to look up hostnames and arbitrary DNS Resource Records via_ `systemd-resolved` _'s bus APIs_

_(This is a longer explanation how to use some parts of_ `systemd-resolved` _bus API. If you are just looking for an API reference, consult the [bus API documentation](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html) instead.)_

_`systemd-resolved`_ provides a set of APIs on the bus for resolving DNS resource records. These are:

1. _ResolveHostname()_ for resolving hostnames to acquire their IP addresses
2. _ResolveAddress()_ for the reverse operation: acquire the hostname for an IP address
3. _ResolveService()_ for resolving a DNS-SD or SRV service
4. _ResolveRecord()_ for resolving arbitrary resource records.

Below you'll find examples for two of these calls, to show how to use them.
Note that glibc offers similar (and more portable) calls in _getaddrinfo()_, _getnameinfo()_ and _res\_query()_.
Of these _getaddrinfo()_ and _getnameinfo()_ are directed to the calls above via the _nss-resolve_ NSS module, but _req\_query()_ is not.
There are a number of reasons why it might be preferable to invoke `systemd-resolved`'s bus calls rather than the glibc APIs:

1. Bus APIs are naturally asynchronous, which the glibc APIs generally are not.
2. The bus calls above pass back substantially more information about the resolved data, including where and how the data was found
  (i.e. which protocol was used: DNS, LLMNR, MulticastDNS, and on which network interface), and most importantly, whether the data could be authenticated via DNSSEC.
  This in particular makes these APIs useful for retrieving certificate data from the DNS, in order to implement DANE, SSHFP, OPENGPGKEY and IPSECKEY clients.
3. _ResolveService()_ knows no counterpart in glibc, and has the benefit of being a single call that collects all data necessary to connect to a DNS-SD or pure SRV service in one step.
4. _ResolveRecord()_ in contrast to _res\_query()_ supports LLMNR and MulticastDNS as protocols on top of DNS, and makes use of `systemd-resolved`'s local DNS record cache.
  The processing of the request is done in the sandboxed `systemd-resolved` process rather than in the local process, and all packets are pre-validated.
  Because this relies on `systemd-resolved` the per-interface DNS zone handling is supported.

Of course, by using `systemd-resolved` you lose some portability, but this could be handled via an automatic fallback to the glibc counterparts.

Note that the various resolver calls provided by `systemd-resolved` will consult `/etc/hosts` and synthesize resource records for these entries in order to ensure that this file is honoured fully.

The examples below use the _sd-bus_ D-Bus client implementation, which is part of _libsystemd_.
Any other D-Bus library, including the original _libdbus_ or _GDBus_ may be used too.

## Resolving a Hostname

To resolve a hostname use the _ResolveHostname()_ call. For details on the function parameters see the [bus API documentation](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html).

This example specifies `AF_UNSPEC` as address family for the requested address.
This means both an _AF\_INET_ (A) and an _AF\_INET6_ (AAAA) record is looked for, depending on whether the local system has configured IPv4 and/or IPv6 connectivity.
It is generally recommended to request `AF_UNSPEC` addresses for best compatibility with both protocols, in particular on dual-stack systems.

The example specifies a network interface index of "0", i.e. does not specify any at all, so that the request may be done on any.
Note that the interface index is primarily relevant for LLMNR and MulticastDNS lookups, which distinguish different scopes for each network interface index.

This examples makes no use of either the input flags parameter, nor the output flags parameter.
See the _ResolveRecord()_ example below for information how to make use of the _SD\_RESOLVED\_AUTHENTICATED_ bit in the returned flags parameter.

```c
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <systemd/sd-bus.h>

int main(int argc, char*argv[]) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = NULL;
        const char *canonical;
        sd_bus *bus = NULL;
        uint64_t flags;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                fprintf(stderr, "Failed to open system bus: %s\n", strerror(-r));
                goto finish;
        }

        r = sd_bus_call_method(bus,
                               "org.freedesktop.resolve1",
                               "/org/freedesktop/resolve1",
                               "org.freedesktop.resolve1.Manager",
                               "ResolveHostname",
                               &error,
                               &reply,
                               "isit",
                               0,                                        /* Network interface index where to look (0 means any) */
                               argc >= 2 ? argv[1] : "www.github.com",   /* Hostname */
                               AF_UNSPEC,                                /* Which address family to look for */
                               UINT64_C(0));                             /* Input flags parameter */
        if (r < 0) {
               fprintf(stderr, "Failed to resolve hostnme: %s\n", error.message);
                sd_bus_error_free(&error);
                goto finish;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(iiay)");
        if (r < 0)
                goto parse_failure;

        for (;;) {
                char buf[INET6_ADDRSTRLEN];
                int ifindex, family;
                const void *data;
                size_t length;

                r = sd_bus_message_enter_container(reply, 'r', "iiay");
                if (r < 0)
                        goto parse_failure;
                if (r == 0)  /* Reached end of array */
                        break;
                r = sd_bus_message_read(reply, "ii", &ifindex, &family);
                if (r < 0)
                        goto parse_failure;
                r = sd_bus_message_read_array(reply, 'y', &data, &length);
                if (r < 0)
                        goto parse_failure;
                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto parse_failure;

                printf("Found IP address %s on interface %i.\n", inet_ntop(family, data, buf, sizeof(buf)), ifindex);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto parse_failure;
        r = sd_bus_message_read(reply, "st", &canonical, &flags);
        if (r < 0)
                goto parse_failure;

        printf("Canonical name is %s\n", canonical);
        goto finish;

parse_failure:
        fprintf(stderr, "Parse failure: %s\n", strerror(-r));

finish:
        sd_bus_message_unref(reply);
        sd_bus_flush_close_unref(bus);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```

Compile this with a command line like the following (under the assumption you save the sources above as `addrtest.c`):

```
gcc addrtest.c -o addrtest -Wall `pkg-config --cflags --libs libsystemd`
```

## Resolving an Arbitrary DNS Resource Record

Use `ResolveRecord()` in order to resolve arbitrary resource records. The call will return the binary RRset data.
This calls is useful to acquire resource records for which no high-level calls such as ResolveHostname(), ResolveAddress() and ResolveService() exist.
In particular RRs such as MX, SSHFP, TLSA, CERT, OPENPGPKEY or IPSECKEY may be requested via this API.

This example also shows how to determine whether the acquired data has been authenticated via DNSSEC (or another means) by checking the `SD_RESOLVED_AUTHENTICATED` bit in the
returned `flags` parameter.

This example contains a simple MX record parser.
Note that the data comes pre-validated from `systemd-resolved`, hence we allow the example to parse the record slightly sloppily, to keep the example brief.
For details on the MX RR binary format, see [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.txt).

For details on the function parameters see the [bus API documentation](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html).

```c
#include <assert.h>
#include <endian.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>

#define DNS_CLASS_IN 1U
#define DNS_TYPE_MX 15U

#define SD_RESOLVED_AUTHENTICATED (UINT64_C(1) << 9)

static const uint8_t* print_name(const uint8_t* p) {
        bool dot = false;
        for (;;) {
                if (*p == 0)
                        return p + 1;
                if (dot)
                        putchar('.');
                else
                        dot = true;
                printf("%.*s", (int) *p, (const char*) p + 1);
                p += *p + 1;
        }
}

static void process_mx(const void *rr, size_t sz) {
        uint16_t class, type, rdlength, preference;
        const uint8_t *p = rr;
        uint32_t ttl;

        fputs("Found MX: ", stdout);
        p = print_name(p);

        memcpy(&type, p, sizeof(uint16_t));
        p += sizeof(uint16_t);
        memcpy(&class, p, sizeof(uint16_t));
        p += sizeof(uint16_t);
        memcpy(&ttl, p, sizeof(uint32_t));
        p += sizeof(uint32_t);
        memcpy(&rdlength, p, sizeof(uint16_t));
        p += sizeof(uint16_t);
        memcpy(&preference, p, sizeof(uint16_t));
        p += sizeof(uint16_t);

        assert(be16toh(type) == DNS_TYPE_MX);
        assert(be16toh(class) == DNS_CLASS_IN);
        printf(" preference=%u ", be16toh(preference));

        p = print_name(p);
        putchar('\n');

        assert(p == (const uint8_t*) rr + sz);
}

int main(int argc, char*argv[]) {
        sd_bus_error error = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = NULL;
        sd_bus *bus = NULL;
        uint64_t flags;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0) {
                fprintf(stderr, "Failed to open system bus: %s\n", strerror(-r));
                goto finish;
        }

        r = sd_bus_call_method(bus,
                               "org.freedesktop.resolve1",
                               "/org/freedesktop/resolve1",
                               "org.freedesktop.resolve1.Manager",
                               "ResolveRecord",
                               &error,
                               &reply,
                               "isqqt",
                               0,                                  /* Network interface index where to look (0 means any) */
                               argc >= 2 ? argv[1] : "gmail.com",  /* Domain name */
                               DNS_CLASS_IN,                       /* DNS RR class */
                               DNS_TYPE_MX,                        /* DNS RR type */
                               UINT64_C(0));                       /* Input flags parameter */
        if (r < 0) {
                fprintf(stderr, "Failed to resolve record: %s\n", error.message);
                sd_bus_error_free(&error);
                goto finish;
        }

        r = sd_bus_message_enter_container(reply, 'a', "(iqqay)");
        if (r < 0)
                goto parse_failure;

        for (;;) {
                uint16_t class, type;
                const void *data;
                size_t length;
                int ifindex;

                r = sd_bus_message_enter_container(reply, 'r', "iqqay");
                if (r < 0)
                        goto parse_failure;
                if (r == 0)  /* Reached end of array */
                        break;
                r = sd_bus_message_read(reply, "iqq", &ifindex, &class, &type);
                if (r < 0)
                        goto parse_failure;
                r = sd_bus_message_read_array(reply, 'y', &data, &length);
                if (r < 0)
                        goto parse_failure;
                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        goto parse_failure;

                process_mx(data, length);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                goto parse_failure;
        r = sd_bus_message_read(reply, "t", &flags);
        if (r < 0)
                goto parse_failure;

        printf("Response is authenticated: %s\n", flags & SD_RESOLVED_AUTHENTICATED ? "yes" : "no");
        goto finish;

parse_failure:
        fprintf(stderr, "Parse failure: %s\n", strerror(-r));

finish:
        sd_bus_message_unref(reply);
        sd_bus_flush_close_unref(bus);
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
   }
```

Compile this with a command line like the following (under the assumption you save the sources above as `rrtest.c`):

```
gcc rrtest.c -o rrtest -Wall `pkg-config --cflags --libs libsystemd`
```
