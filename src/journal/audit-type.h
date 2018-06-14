/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"

const char *audit_type_to_string(int type);
int audit_type_from_string(const char *s);

/* This is inspired by DNS TYPEnnn formatting */
#define audit_type_name_alloca(type)                                    \
        ({                                                              \
                const char *_s_;                                        \
                _s_ = audit_type_to_string(type);                       \
                if (!_s_) {                                             \
                        _s_ = alloca(STRLEN("AUDIT") + DECIMAL_STR_MAX(int)); \
                        sprintf((char*) _s_, "AUDIT%04i", type);        \
                }                                                       \
                _s_;                                                    \
        })
