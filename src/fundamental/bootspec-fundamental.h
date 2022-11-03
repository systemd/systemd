/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "string-util-fundamental.h"

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
                const sd_char **ret_sort_key);
