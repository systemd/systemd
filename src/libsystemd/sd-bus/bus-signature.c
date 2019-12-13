/* SPDX-License-Identifier: LGPL-2.1+ */

#include <util.h>

#include "sd-bus.h"

#include "bus-signature.h"
#include "bus-type.h"

static int signature_element_length_internal(
                const char *s,
                bool allow_dict_entry,
                unsigned array_depth,
                unsigned struct_depth,
                size_t *l) {

        int r;

        if (!s)
                return -EINVAL;

        assert(l);

        if (bus_type_is_basic(*s) || *s == SD_BUS_TYPE_VARIANT) {
                *l = 1;
                return 0;
        }

        if (*s == SD_BUS_TYPE_ARRAY) {
                size_t t;

                if (array_depth >= 32)
                        return -EINVAL;

                r = signature_element_length_internal(s + 1, true, array_depth+1, struct_depth, &t);
                if (r < 0)
                        return r;

                *l = t + 1;
                return 0;
        }

        if (*s == SD_BUS_TYPE_STRUCT_BEGIN) {
                const char *p = s + 1;

                if (struct_depth >= 32)
                        return -EINVAL;

                while (*p != SD_BUS_TYPE_STRUCT_END) {
                        size_t t;

                        r = signature_element_length_internal(p, false, array_depth, struct_depth+1, &t);
                        if (r < 0)
                                return r;

                        p += t;
                }

                if (p - s < 2)
                        /* D-Bus spec: Empty structures are not allowed; there
                         * must be at least one type code between the parentheses.
                         */
                        return -EINVAL;

                *l = p - s + 1;
                return 0;
        }

        if (*s == SD_BUS_TYPE_DICT_ENTRY_BEGIN && allow_dict_entry) {
                const char *p = s + 1;
                unsigned n = 0;

                if (struct_depth >= 32)
                        return -EINVAL;

                while (*p != SD_BUS_TYPE_DICT_ENTRY_END) {
                        size_t t;

                        if (n == 0 && !bus_type_is_basic(*p))
                                return -EINVAL;

                        r = signature_element_length_internal(p, false, array_depth, struct_depth+1, &t);
                        if (r < 0)
                                return r;

                        p += t;
                        n++;
                }

                if (n != 2)
                        return -EINVAL;

                *l = p - s + 1;
                return 0;
        }

        return -EINVAL;
}

int signature_element_length(const char *s, size_t *l) {
        return signature_element_length_internal(s, true, 0, 0, l);
}

bool signature_is_single(const char *s, bool allow_dict_entry) {
        int r;
        size_t t;

        if (!s)
                return false;

        r = signature_element_length_internal(s, allow_dict_entry, 0, 0, &t);
        if (r < 0)
                return false;

        return s[t] == 0;
}

bool signature_is_pair(const char *s) {

        if (!s)
                return false;

        if (!bus_type_is_basic(*s))
                return false;

        return signature_is_single(s + 1, false);
}

bool signature_is_valid(const char *s, bool allow_dict_entry) {
        const char *p;
        int r;

        if (!s)
                return false;

        p = s;
        while (*p) {
                size_t t;

                r = signature_element_length_internal(p, allow_dict_entry, 0, 0, &t);
                if (r < 0)
                        return false;

                p += t;
        }

        return p - s <= SD_BUS_MAXIMUM_SIGNATURE_LENGTH;
}
