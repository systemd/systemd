/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

int dm_clone_create_device(
                const char *name,
                const char *source_dev,
                const char *dest_dev,
                const char *metadata_dev);

int dm_clone_send_message(const char *name, const char *message);

