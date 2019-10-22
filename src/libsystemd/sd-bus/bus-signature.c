/* SPDX-License-Identifier: LGPL-2.1+ */

#include "sd-bus.h"

#include "bus-signature.h"
#include "bus-type.h"

static int signature_element_length_internal(
                const char *s,
                bool allow_dict_entry,
                unsigned array_depth,
                unsigned struct_depth,
                bool *fixed_size) {

        int r;

        if (!s)
                return -EINVAL;

        if (bus_type_is_basic(*s)) {
                if (fixed_size)
                        *fixed_size = !IN_SET(*s, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH, SD_BUS_TYPE_SIGNATURE);
                return 1;
        }

        if (*s == SD_BUS_TYPE_VARIANT) {
                if (fixed_size)
                        *fixed_size = false;
                return 1;
        }

        if (*s == SD_BUS_TYPE_ARRAY) {
                if (array_depth >= 32)
                        return -EINVAL;

                r = signature_element_length_internal(s + 1, true, array_depth+1, struct_depth, NULL);
                if (r < 0)
                        return r;
                if (fixed_size)
                        *fixed_size = false;
                return r + 1;
        }

        if (*s == SD_BUS_TYPE_STRUCT_BEGIN) {
                const char *p = s + 1;
                bool fixed_size_nested = true;

                if (struct_depth >= 32)
                        return -EINVAL;

                while (*p != SD_BUS_TYPE_STRUCT_END) {
                        bool fixed_size_elem;

                        r = signature_element_length_internal(p, false, array_depth, struct_depth+1, &fixed_size_elem);
                        if (r < 0)
                                return r;
                        p += r;
                        if (!fixed_size_elem)
                                fixed_size_nested = false;
                }

                if (p - s < 2)
                        /* D-Bus spec: Empty structures are not allowed; there
                         * must be at least one type code between the parentheses.
                         */
                        return -EINVAL;

                if (fixed_size)
                        *fixed_size = fixed_size_nested;
                return p - s + 1;
        }

        if (*s == SD_BUS_TYPE_DICT_ENTRY_BEGIN && allow_dict_entry) {
                const char *p = s + 1;
                unsigned n = 0;

                if (struct_depth >= 32)
                        return -EINVAL;

                while (*p != SD_BUS_TYPE_DICT_ENTRY_END) {
                        if (n == 0 && !bus_type_is_basic(*p))
                                return -EINVAL;

                        r = signature_element_length_internal(p, false, array_depth, struct_depth+1, NULL);
                        if (r < 0)
                                return r;
                        p += r;
                        n++;
                }

                if (n != 2)
                        return -EINVAL;

                if (fixed_size)
                        *fixed_size = false;
                return p - s + 1;
        }

        return -EINVAL;
}

int signature_element_length_full(const char *s, bool *fixed_size) {
        return signature_element_length_internal(s, true, 0, 0, fixed_size);
}

bool signature_is_single(const char *s, bool allow_dict_entry) {
        int r;

        r = signature_element_length_internal(s, allow_dict_entry, 0, 0, NULL);
        if (r < 0)
                return false;

        return !s[r];
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

        for (p = s; *p; p += r) {
                r = signature_element_length_internal(p, allow_dict_entry, 0, 0, NULL);
                if (r < 0)
                        return false;
        }

        return p - s <= SD_BUS_MAXIMUM_SIGNATURE_LENGTH;
}
