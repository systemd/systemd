/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

_sync_ bool signature_is_single(const char *s, bool allow_dict_entry);
_sync_ bool signature_is_pair(const char *s);
_sync_ bool signature_is_valid(const char *s, bool allow_dict_entry);

_sync_ int signature_element_length(const char *s, size_t *l);
