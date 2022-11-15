/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec-fundamental.h"

bool bootspec_pick_name_version_sort_key(
                const sd_char *os_pretty_name,
                const sd_char *os_image_id,
                const sd_char *os_name,
                const sd_char *os_id,
                const sd_char *os_image_version,
                const sd_char *os_version,
                const sd_char *os_version_id,
                const sd_char *os_build_id,
                const sd_char **ret_name,
                const sd_char **ret_version,
                const sd_char **ret_sort_key) {

        const sd_char *good_name, *good_version, *good_sort_key;

        /* Find the best human readable title, version string and sort key for a boot entry (using the
         * os-release(5) fields). Precise is preferred over vague, and human readable over machine
         * readable. Thus:
         *
         * 1. First priority gets the PRETTY_NAME field, which is the primary string intended for display,
         *    and should already contain both a nice description and a version indication (if that concept
         *    applies).
         *
         * 2. Otherwise we go for IMAGE_ID and IMAGE_VERSION (thus we show details about the image,
         *    i.e. specific combination of packages and configuration), if that concept applies.
         *
         * 3. Otherwise we go for NAME and VERSION (i.e. human readable OS name and version)
         *
         * 4. Otherwise we go for ID and VERSION_ID (i.e. machine readable OS name and version)
         *
         * 5. Finally, for the version we'll use BUILD_ID (i.e. a machine readable version that identifies
         *    the original OS build used during installation)
         *
         * Note that the display logic will show only the name by default, except if that isn't unique in
         * which case the version is shown too.
         *
         * Note that name/version determined here are used only for display purposes. Boot entry preference
         * sorting (i.e. algorithmic ordering of boot entries) is done based on the order of the sort key (if
         * defined) or entry "id" string (i.e. entry file name) otherwise. */

        good_name = os_pretty_name ?: (os_image_id ?: (os_name ?: os_id));
        good_version = os_image_version ?: (os_version ?: (os_version_id ? : os_build_id));
        good_sort_key = os_image_id ?: os_id;

        if (!good_name)
                return false;

        if (ret_name)
                *ret_name = good_name;

        if (ret_version)
                *ret_version = good_version;

        if (ret_sort_key)
                *ret_sort_key = good_sort_key;

        return true;
}
