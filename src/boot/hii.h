/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

/* Queries the firmware's HII database for the currently-active keyboard layout and returns the RFC 4646
 * language tag (e.g. u"de-DE") embedded in the layout description bundle. Returns NULL if the protocol
 * is not provided, the table is malformed, or no language tag is present. */
char16_t *hii_query_keyboard_layout_language(void);
