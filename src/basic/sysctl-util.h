/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "macro.h"
#include "stdio-util.h"
#include "string-util.h"

char *sysctl_normalize(char *s);
int sysctl_read(const char *property, char **value);
int sysctl_write(const char *property, const char *value);
int sysctl_writef(const char *property, const char *format, ...) _printf_(2, 3);

int sysctl_read_ip_property(int af, const char *ifname, const char *property, char **ret);
int sysctl_write_ip_property(int af, const char *ifname, const char *property, const char *value);
static inline int sysctl_write_ip_property_boolean(int af, const char *ifname, const char *property, bool value) {
        return sysctl_write_ip_property(af, ifname, property, one_zero(value));
}

int sysctl_write_ip_neigh_property(int af, const char *ifname, const char *property, const char *value);
int sysctl_write_ip_neigh_property_int(int af, const char *ifname, const char *property, int value);
static inline int sysctl_write_ip_neigh_property_int(int af, const char *ifname, const char *property, int value) {
        char buf[DECIMAL_STR_MAX(type)];
        xsprintf(buf, "%i", value);
        return sysctl_write_ip_neigh_property(af, ifname, property, buf);
}

#define DEFINE_SYSCTL_WRITE_IP_PROPERTY(name, type, format)           \
        static inline int sysctl_write_ip_property_##name(int af, const char *ifname, const char *property, type value) { \
                char buf[DECIMAL_STR_MAX(type)];                        \
                xsprintf(buf, format, value);                           \
                return sysctl_write_ip_property(af, ifname, property, buf); \
        }

DEFINE_SYSCTL_WRITE_IP_PROPERTY(int, int, "%i");
DEFINE_SYSCTL_WRITE_IP_PROPERTY(uint32, uint32_t, "%" PRIu32);
