/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "forward.h"
#include "os-util.h"

typedef enum VOAPurpose {
        VOA_PURPOSE_IMAGE,
        _VOA_PURPOSE_MAX,
        _VOA_PURPOSE_INVALID = -EINVAL,
} VOAPurpose;

typedef enum VOAContext {
        /* These are matching with ImageClass src/basic/os-util.h, but there is no reason there can't be more added*/
        VOA_CONTEXT_MACHINE = IMAGE_MACHINE,
        VOA_CONTEXT_PORTABLE = IMAGE_PORTABLE,
        VOA_CONTEXT_SYSEXT = IMAGE_SYSEXT,
        VOA_CONTEXT_CONFEXT = IMAGE_CONFEXT,
        _VOA_CONTEXT_MAX,
        _VOA_CONTEXT_INVALID = -EINVAL,
} VOAContext;

typedef enum VOATechnology {
        VOA_TECHNOLOGY_X509,
        VOA_TECHNOLOGY_GPG,
        VOA_TECHNOLOGY_SSH,
        _VOA_TECHNOLOGY_MAX,
        _VOA_TECHNOLOGY_INVALID = -EINVAL,
} VOATechnology;

DECLARE_STRING_TABLE_LOOKUP(voa_purpose, VOAPurpose);
DECLARE_STRING_TABLE_LOOKUP(voa_context, VOAContext);
DECLARE_STRING_TABLE_LOOKUP(voa_technology, VOATechnology);

int acquire_voa_paths(char ***ret, VOAPurpose purpose, VOAContext context, VOATechnology technology);
