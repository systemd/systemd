/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "util.h"
#include "bus-type.h"
#include "bus-gvariant.h"
#include "bus-signature.h"

int bus_gvariant_get_size(const char *signature) {
        const char *p;
        int sum = 0, r;

        /* For fixed size structs. Fails for variable size structs. */

        p = signature;
        while (*p != 0) {
                size_t n;

                r = signature_element_length(p, &n);
                if (r < 0)
                        return r;
                else {
                        char t[n+1];

                        memcpy(t, p, n);
                        t[n] = 0;

                        r = bus_gvariant_get_alignment(t);
                        if (r < 0)
                                return r;

                        sum = ALIGN_TO(sum, r);
                }

                switch (*p) {

                case SD_BUS_TYPE_BOOLEAN:
                case SD_BUS_TYPE_BYTE:
                        sum += 1;
                        break;

                case SD_BUS_TYPE_INT16:
                case SD_BUS_TYPE_UINT16:
                        sum += 2;
                        break;

                case SD_BUS_TYPE_INT32:
                case SD_BUS_TYPE_UINT32:
                case SD_BUS_TYPE_UNIX_FD:
                        sum += 4;
                        break;

                case SD_BUS_TYPE_INT64:
                case SD_BUS_TYPE_UINT64:
                case SD_BUS_TYPE_DOUBLE:
                        sum += 8;
                        break;

                case SD_BUS_TYPE_STRUCT_BEGIN:
                case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                        char t[n-1];

                        memcpy(t, p + 1, n - 2);
                        t[n - 2] = 0;

                        r = bus_gvariant_get_size(t);
                        if (r < 0)
                                return r;

                        sum += r;
                        break;
                }

                case SD_BUS_TYPE_STRING:
                case SD_BUS_TYPE_OBJECT_PATH:
                case SD_BUS_TYPE_SIGNATURE:
                case SD_BUS_TYPE_ARRAY:
                case SD_BUS_TYPE_VARIANT:
                        return -EINVAL;

                default:
                        assert_not_reached("Unknown signature type");
                }

                p += n;
        }

        r = bus_gvariant_get_alignment(signature);
        if (r < 0)
                return r;

        return ALIGN_TO(sum, r);
}

int bus_gvariant_get_alignment(const char *signature) {
        size_t alignment = 1;
        const char *p;
        int r;

        p = signature;
        while (*p != 0 && alignment < 8) {
                size_t n;
                int a;

                r = signature_element_length(p, &n);
                if (r < 0)
                        return r;

                switch (*p) {

                case SD_BUS_TYPE_BYTE:
                case SD_BUS_TYPE_BOOLEAN:
                case SD_BUS_TYPE_STRING:
                case SD_BUS_TYPE_OBJECT_PATH:
                case SD_BUS_TYPE_SIGNATURE:
                        a = 1;
                        break;

                case SD_BUS_TYPE_INT16:
                case SD_BUS_TYPE_UINT16:
                        a = 2;
                        break;

                case SD_BUS_TYPE_INT32:
                case SD_BUS_TYPE_UINT32:
                case SD_BUS_TYPE_UNIX_FD:
                        a = 4;
                        break;

                case SD_BUS_TYPE_INT64:
                case SD_BUS_TYPE_UINT64:
                case SD_BUS_TYPE_DOUBLE:
                case SD_BUS_TYPE_VARIANT:
                        a = 8;
                        break;

                case SD_BUS_TYPE_ARRAY: {
                        char t[n];

                        memcpy(t, p + 1, n - 1);
                        t[n - 1] = 0;

                        a = bus_gvariant_get_alignment(t);
                        break;
                }

                case SD_BUS_TYPE_STRUCT_BEGIN:
                case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                        char t[n-1];

                        memcpy(t, p + 1, n - 2);
                        t[n - 2] = 0;

                        a = bus_gvariant_get_alignment(t);
                        break;
                }

                default:
                        assert_not_reached("Unknown signature type");
                }

                if (a < 0)
                        return a;

                assert(a > 0 && a <= 8);
                if ((size_t) a > alignment)
                        alignment = (size_t) a;

                p += n;
        }

        return alignment;
}

int bus_gvariant_is_fixed_size(const char *signature) {
        const char *p;
        int r;

        assert(signature);

        p = signature;
        while (*p != 0) {
                size_t n;

                r = signature_element_length(p, &n);
                if (r < 0)
                        return r;

                switch (*p) {

                case SD_BUS_TYPE_STRING:
                case SD_BUS_TYPE_OBJECT_PATH:
                case SD_BUS_TYPE_SIGNATURE:
                case SD_BUS_TYPE_ARRAY:
                case SD_BUS_TYPE_VARIANT:
                        return 0;

                case SD_BUS_TYPE_BYTE:
                case SD_BUS_TYPE_BOOLEAN:
                case SD_BUS_TYPE_INT16:
                case SD_BUS_TYPE_UINT16:
                case SD_BUS_TYPE_INT32:
                case SD_BUS_TYPE_UINT32:
                case SD_BUS_TYPE_UNIX_FD:
                case SD_BUS_TYPE_INT64:
                case SD_BUS_TYPE_UINT64:
                case SD_BUS_TYPE_DOUBLE:
                        break;

                case SD_BUS_TYPE_STRUCT_BEGIN:
                case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                        char t[n-1];

                        memcpy(t, p + 1, n - 2);
                        t[n - 2] = 0;

                        r = bus_gvariant_is_fixed_size(t);
                        if (r <= 0)
                                return r;
                        break;
                }

                default:
                        assert_not_reached("Unknown signature type");
                }

                p += n;
        }

        return true;
}
