/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
 This file is part of systemd.

 Copyright (C) 2013 Tom Gundersen <teg@jklm.no>

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

#include <netinet/ether.h>
#include <linux/if.h>
#include <arpa/inet.h>

#include "net-util.h"
#include "log.h"
#include "utf8.h"
#include "util.h"
#include "conf-parser.h"

bool net_match_config(const struct ether_addr *match_mac,
                      const char *match_path,
                      const char *match_driver,
                      const char *match_type,
                      const char *match_name,
                      const char *dev_mac,
                      const char *dev_path,
                      const char *dev_driver,
                      const char *dev_type,
                      const char *dev_name) {

        if (match_mac) {
                if (!dev_mac || memcmp(match_mac, ether_aton(dev_mac), ETH_ALEN)) {
                        log_debug("Interface MAC address (%s) did not match MACAddress=%s",
                                  dev_mac, ether_ntoa(match_mac));
                        return 0;
                }
        }

        if (match_path) {
                if (!streq_ptr(match_path, dev_path)) {
                        log_debug("Interface persistent path (%s) did not match Path=%s",
                                  dev_path, match_path);
                        return 0;
                }
        }

        if (match_driver) {
                if (!streq_ptr(match_driver, dev_driver)) {
                        log_debug("Interface device driver (%s) did not match Driver=%s",
                                  dev_driver, match_driver);
                        return 0;
                }
        }

        if (match_type) {
                if (!streq_ptr(match_type, dev_type)) {
                        log_debug("Interface type (%s) did not match Type=%s",
                                  dev_type, match_type);
                        return 0;
                }
        }

        if (match_name) {
                if (!streq_ptr(match_name, dev_name)) {
                        log_debug("Interface name (%s) did not match Name=%s",
                                  dev_name, match_name);
                        return 0;
                }
        }

        return 1;
}

int config_parse_ifname(const char *unit,
                        const char *filename,
                        unsigned line,
                        const char *section,
                        unsigned section_line,
                        const char *lvalue,
                        int ltype,
                        const char *rvalue,
                        void *data,
                        void *userdata) {

        char **s = data;
        char *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        if (!ascii_is_valid(n) || strlen(n) >= IFNAMSIZ) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Interface name is not ASCII clean or is too long, ignoring assignment: %s", rvalue);
                free(n);
                return 0;
        }

        free(*s);
        if (*n)
                *s = n;
        else {
                free(n);
                *s = NULL;
        }

        return 0;
}

int config_parse_ifalias(const char *unit,
                         const char *filename,
                         unsigned line,
                         const char *section,
                         unsigned section_line,
                         const char *lvalue,
                         int ltype,
                         const char *rvalue,
                         void *data,
                         void *userdata) {

        char **s = data;
        char *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        if (!ascii_is_valid(n) || strlen(n) >= IFALIASZ) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Interface alias is not ASCII clean or is too long, ignoring assignment: %s", rvalue);
                free(n);
                return 0;
        }

        free(*s);
        if (*n)
                *s = n;
        else {
                free(n);
                *s = NULL;
        }

        return 0;
}

int config_parse_hwaddr(const char *unit,
                        const char *filename,
                        unsigned line,
                        const char *section,
                        unsigned section_line,
                        const char *lvalue,
                        int ltype,
                        const char *rvalue,
                        void *data,
                        void *userdata) {
        struct ether_addr **hwaddr = data;
        struct ether_addr *n;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        n = new0(struct ether_addr, 1);
        if (!n)
                return log_oom();

        r = sscanf(rvalue, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                   &n->ether_addr_octet[0],
                   &n->ether_addr_octet[1],
                   &n->ether_addr_octet[2],
                   &n->ether_addr_octet[3],
                   &n->ether_addr_octet[4],
                   &n->ether_addr_octet[5]);
        if (r != 6) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Not a valid MAC address, ignoring assignment: %s", rvalue);
                free(n);
                return 0;
        }

        free(*hwaddr);
        *hwaddr = n;

        return 0;
}

int net_parse_inaddr(const char *address, unsigned char *family, void *dst) {
        int r;

        assert(address);
        assert(family);
        assert(dst);

        /* IPv4 */
        r = inet_pton(AF_INET, address, dst);
        if (r > 0)
                *family = AF_INET; /* successfully parsed IPv4 address */
        else  if (r < 0)
                return -errno;
        else {
                /* not an IPv4 address, so let's try IPv6 */
                r = inet_pton(AF_INET6, address, dst);
                if (r > 0)
                        *family = AF_INET6; /* successfully parsed IPv6 address */
                else if (r < 0)
                        return -errno;
                else
                        return -EINVAL;
        }

        return 0;
}
