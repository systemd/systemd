/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "types-fundamental.h"

sd_bool bootspec_pick_name_version(
                const sd_char *os_pretty_name,
                const sd_char *os_image_id,
                const sd_char *os_name,
                const sd_char *os_id,
                const sd_char *os_image_version,
                const sd_char *os_version,
                const sd_char *os_version_id,
                const sd_char *os_build_id,
                const sd_char **ret_name,
                const sd_char **ret_version);
