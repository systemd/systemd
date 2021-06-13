/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-signature.h"
#include "bus-type.h"

static int element_alignment(const char element) {
        switch (element) {
        case SD_BUS_TYPE_BYTE:
        case SD_BUS_TYPE_BOOLEAN:
        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:
        case SD_BUS_TYPE_SIGNATURE:
                return 1;

        case SD_BUS_TYPE_INT16:
        case SD_BUS_TYPE_UINT16:
                return 2;

        case SD_BUS_TYPE_INT32:
        case SD_BUS_TYPE_UINT32:
        case SD_BUS_TYPE_UNIX_FD:
                return 4;

        case SD_BUS_TYPE_INT64:
        case SD_BUS_TYPE_UINT64:
        case SD_BUS_TYPE_DOUBLE:
        case SD_BUS_TYPE_VARIANT:
                return 8;

        case SD_BUS_TYPE_ARRAY:
        case SD_BUS_TYPE_STRUCT_BEGIN:
        case SD_BUS_TYPE_DICT_ENTRY_BEGIN:
                return 0; /* variable */
        default:
                assert_not_reached("Unknown signature type");
        }
}

static int gvariant_element_size(const char element) {
        switch (element) {
        case SD_BUS_TYPE_BOOLEAN:
        case SD_BUS_TYPE_BYTE:
                return 1;

        case SD_BUS_TYPE_INT16:
        case SD_BUS_TYPE_UINT16:
                return 2;

        case SD_BUS_TYPE_INT32:
        case SD_BUS_TYPE_UINT32:
        case SD_BUS_TYPE_UNIX_FD:
                return 4;

        case SD_BUS_TYPE_INT64:
        case SD_BUS_TYPE_UINT64:
        case SD_BUS_TYPE_DOUBLE:
                return 8;

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:
        case SD_BUS_TYPE_SIGNATURE:
                return -EINVAL;

        default:
                assert_not_reached("Unknown signature type");
        }
}

static int signature_element_length_internal(
                const char *s,
                bool allow_dict_entry,
                unsigned array_depth,
                unsigned struct_depth,
                bool *fixed_size,
                int *alignment,
                int *gvariant_size) {

        int r;

        if (!s)
                return -EINVAL;

        if (bus_type_is_basic(*s)) {
                if (fixed_size)
                        *fixed_size = !IN_SET(*s, SD_BUS_TYPE_STRING, SD_BUS_TYPE_OBJECT_PATH, SD_BUS_TYPE_SIGNATURE);
                if (alignment)
                        *alignment = element_alignment(*s);
                if (gvariant_size)
                        *gvariant_size = gvariant_element_size(*s);
                return 1;
        }

        if (*s == SD_BUS_TYPE_VARIANT) {
                if (fixed_size)
                        *fixed_size = false;
                if (alignment)
                        *alignment = element_alignment(*s);
                if (gvariant_size)
                        *gvariant_size = -EINVAL;
                return 1;
        }

        if (*s == SD_BUS_TYPE_ARRAY) {
                if (array_depth >= 32)
                        return -EINVAL;

                r = signature_element_length_internal(s + 1, true, array_depth+1, struct_depth, NULL, alignment, NULL);
                if (r < 0)
                        return r;
                if (fixed_size)
                        *fixed_size = false;
                if (gvariant_size)
                        *gvariant_size = -EINVAL;
                return r + 1;
        }

        if (*s == SD_BUS_TYPE_STRUCT_BEGIN) {
                const char *p = s + 1;
                bool fixed_size_nested = true;
                int alignment_nested = 1, size_nested = 0;

                if (struct_depth >= 32)
                        return -EINVAL;

                while (*p != SD_BUS_TYPE_STRUCT_END) {
                        bool fixed_size_elem;
                        int alignment_elem, size_elem;

                        r = signature_element_length_internal(p, false, array_depth, struct_depth+1,
                                                              &fixed_size_elem, &alignment_elem, &size_elem);
                        if (r < 0)
                                return r;
                        p += r;
                        if (!fixed_size_elem)
                                fixed_size_nested = false;
                        alignment_nested = MAX(alignment_nested, alignment_elem);
                        if (size_nested >= 0) {
                                if (size_elem < 0)
                                        size_nested = size_elem;
                                else
                                        size_nested += size_elem;
                        }
                }

                if (p - s < 2)
                        /* D-Bus spec: Empty structures are not allowed; there
                         * must be at least one type code between the parentheses.
                         */
                        return -EINVAL;

                if (fixed_size)
                        *fixed_size = fixed_size_nested;
                if (alignment)
                        *alignment = alignment_nested;
                if (gvariant_size)
                        *gvariant_size = size_nested < 0 ? size_nested : (int) ALIGN_TO(size_nested, alignment_nested);
                return p - s + 1;
        }

        if (*s == SD_BUS_TYPE_DICT_ENTRY_BEGIN && allow_dict_entry) {
                const char *p = s + 1;
                unsigned n = 0;
                int alignment_nested = 1, size_nested = 0;

                if (struct_depth >= 32)
                        return -EINVAL;

                while (*p != SD_BUS_TYPE_DICT_ENTRY_END) {
                        int alignment_elem, size_elem;

                        if (n == 0 && !bus_type_is_basic(*p))
                                return -EINVAL;

                        r = signature_element_length_internal(p, false, array_depth, struct_depth+1,
                                                              NULL, &alignment_elem, &size_elem);
                        if (r < 0)
                                return r;
                        p += r;
                        n++;
                        alignment_nested = MAX(alignment_nested, alignment_elem);
                        if (size_nested >= 0) {
                                if (size_elem < 0)
                                        size_nested = size_elem;
                                else
                                        size_nested += size_elem;
                        }
                }

                if (n != 2)
                        return -EINVAL;

                if (fixed_size)
                        *fixed_size = false;
                if (alignment)
                        *alignment = alignment_nested;
                if (gvariant_size)
                        *gvariant_size = size_nested < 0 ? size_nested : (int) ALIGN_TO(size_nested, alignment_nested);
                return p - s + 1;
        }

        return -EINVAL;
}

int signature_element_length_full(const char *s, bool *fixed_size, int *alignment, int *gvariant_size) {
        return signature_element_length_internal(s, true, 0, 0, fixed_size, alignment, gvariant_size);
}

bool signature_is_single(const char *s, bool allow_dict_entry) {
        int r;

        r = signature_element_length_internal(s, allow_dict_entry, 0, 0, NULL, NULL, NULL);
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
                r = signature_element_length_internal(p, allow_dict_entry, 0, 0, NULL, NULL, NULL);
                if (r < 0)
                        return false;
        }

        return p - s <= SD_BUS_MAXIMUM_SIGNATURE_LENGTH;
}
