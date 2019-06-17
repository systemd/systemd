/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "macro.h"

/* So here's the deal: net_id is supposed to be an exercise in providing stable names for network devices. However, we
 * also want to keep updating the naming scheme used in future versions of net_id. These two goals of course are
 * contradictory: on one hand we want things to not change and on the other hand we want them to improve. Our way out
 * of this dilemma is to introduce the "naming scheme" concept: each time we improve the naming logic we define a new
 * flag for it. Then, we keep a list of schemes, each identified by a name associated with the flags it implements. Via
 * a kernel command line and environment variable we then allow the user to pick the scheme they want us to follow:
 * installers could "freeze" the used scheme at the moment of installation this way.
 *
 * Developers: each time you tweak the naming logic here, define a new flag below, and condition the tweak with
 * it. Each time we do a release we'll then add a new scheme entry and include all newly defined flags.
 *
 * Note that this is only half a solution to the problem though: not only udev/net_id gets updated all the time, the
 * kernel gets too. And thus a kernel that previously didn't expose some sysfs attribute we look for might eventually
 * do, and thus affect our naming scheme too. Thus, enforcing a naming scheme will make interfacing more stable across
 * OS versions, but not fully stabilize them. */
typedef enum NamingSchemeFlags {
        /* First, the individual features */
        NAMING_SR_IOV_V            = 1 << 0, /* Use "v" suffix for SR-IOV, see 609948c7043a */
        NAMING_NPAR_ARI            = 1 << 1, /* Use NPAR "ARI", see 6bc04997b6ea */
        NAMING_INFINIBAND          = 1 << 2, /* Use "ib" prefix for infiniband, see 938d30aa98df */
        NAMING_ZERO_ACPI_INDEX     = 1 << 3, /* Use zero acpi_index field, see d81186ef4f6a */
        NAMING_ALLOW_RERENAMES     = 1 << 4, /* Allow re-renaming of devices, see #9006 */
        NAMING_STABLE_VIRTUAL_MACS = 1 << 5, /* Use device name to generate MAC, see 6d3646406560 */
        NAMING_NETDEVSIM           = 1 << 6, /* Generate names for netdevsim devices, see eaa9d507d855 */
        NAMING_LABEL_NOPREFIX      = 1 << 7, /* Don't prepend ID_NET_LABEL_ONBOARD with interface type prefix */

        /* And now the masks that combine the features above */
        NAMING_V238 = 0,
        NAMING_V239 = NAMING_V238 | NAMING_SR_IOV_V | NAMING_NPAR_ARI,
        NAMING_V240 = NAMING_V239 | NAMING_INFINIBAND | NAMING_ZERO_ACPI_INDEX | NAMING_ALLOW_RERENAMES,
        NAMING_V241 = NAMING_V240 | NAMING_STABLE_VIRTUAL_MACS,
        NAMING_V243 = NAMING_V241 | NAMING_NETDEVSIM | NAMING_LABEL_NOPREFIX,

        _NAMING_SCHEME_FLAGS_INVALID = -1,
} NamingSchemeFlags;

typedef struct NamingScheme {
        const char *name;
        NamingSchemeFlags flags;
} NamingScheme;

const NamingScheme* naming_scheme(void);

static inline bool naming_scheme_has(NamingSchemeFlags flags) {
        return FLAGS_SET(naming_scheme()->flags, flags);
}
