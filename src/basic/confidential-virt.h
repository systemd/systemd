/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "errno-list.h"
#include "macro.h"

typedef enum ConfidentialVirtualization {
        CONFIDENTIAL_VIRTUALIZATION_NONE = 0,

        CONFIDENTIAL_VIRTUALIZATION_SEV,
        CONFIDENTIAL_VIRTUALIZATION_SEV_ES,
        CONFIDENTIAL_VIRTUALIZATION_SEV_SNP,
        CONFIDENTIAL_VIRTUALIZATION_TDX,
        CONFIDENTIAL_VIRTUALIZATION_PROTVIRT,
        CONFIDENTIAL_VIRTUALIZATION_CCA,

        _CONFIDENTIAL_VIRTUALIZATION_MAX,
        _CONFIDENTIAL_VIRTUALIZATION_INVALID = -EINVAL,
        _CONFIDENTIAL_VIRTUALIZATION_ERRNO_MAX = -ERRNO_MAX, /* ensure full range of errno fits into this enum */
} ConfidentialVirtualization;

ConfidentialVirtualization detect_confidential_virtualization(void);

const char* confidential_virtualization_to_string(ConfidentialVirtualization v) _const_;
ConfidentialVirtualization confidential_virtualization_from_string(const char *s) _pure_;
