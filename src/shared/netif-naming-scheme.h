/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"
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
        NAMING_SR_IOV_V                  = 1 << 0, /* Use "v" suffix for SR-IOV, see 609948c7043a */
        NAMING_NPAR_ARI                  = 1 << 1, /* Use NPAR "ARI", see 6bc04997b6ea */
        NAMING_INFINIBAND                = 1 << 2, /* Use "ib" prefix for infiniband, see 938d30aa98df */
        NAMING_ZERO_ACPI_INDEX           = 1 << 3, /* Use zero acpi_index field, see d81186ef4f6a */
        NAMING_ALLOW_RERENAMES           = 1 << 4, /* Allow re-renaming of devices, see #9006 */
        NAMING_STABLE_VIRTUAL_MACS       = 1 << 5, /* Use device name to generate MAC, see 6d3646406560 */
        NAMING_NETDEVSIM                 = 1 << 6, /* Generate names for netdevsim devices, see eaa9d507d855 */
        NAMING_LABEL_NOPREFIX            = 1 << 7, /* Don't prepend ID_NET_LABEL_ONBOARD with interface type prefix */
        NAMING_NSPAWN_LONG_HASH          = 1 << 8, /* Shorten nspawn interfaces by including 24bit hash, instead of simple truncation  */
        NAMING_BRIDGE_NO_SLOT            = 1 << 9, /* Don't use PCI hotplug slot information if the corresponding device is a PCI bridge */
        NAMING_SLOT_FUNCTION_ID          = 1 << 10, /* Use function_id if present to identify PCI hotplug slots */
        NAMING_16BIT_INDEX               = 1 << 11, /* Allow full 16-bit for the onboard index */
        NAMING_REPLACE_STRICTLY          = 1 << 12, /* Use udev_replace_ifname() for NAME= rule */
        NAMING_XEN_VIF                   = 1 << 13, /* Generate names for Xen netfront devices */
        NAMING_BRIDGE_MULTIFUNCTION_SLOT = 1 << 14, /* Use PCI hotplug slot information associated with bridge, but only if PCI device is multifunction.
                                                     * This is disabled since v255, as it seems not to work at least for some setups. See issue #28929. */
        NAMING_DEVICETREE_ALIASES        = 1 << 15, /* Generate names from devicetree aliases */
        NAMING_USB_HOST                  = 1 << 16, /* Generate names for usb host */
        NAMING_SR_IOV_R                  = 1 << 17, /* Use "r" suffix for SR-IOV VF representors */

        /* And now the masks that combine the features above */
        NAMING_V238 = 0,
        NAMING_V239 = NAMING_V238 | NAMING_SR_IOV_V | NAMING_NPAR_ARI,
        NAMING_V240 = NAMING_V239 | NAMING_INFINIBAND | NAMING_ZERO_ACPI_INDEX | NAMING_ALLOW_RERENAMES,
        NAMING_V241 = NAMING_V240 | NAMING_STABLE_VIRTUAL_MACS,
        NAMING_V243 = NAMING_V241 | NAMING_NETDEVSIM | NAMING_LABEL_NOPREFIX,
        NAMING_V245 = NAMING_V243 | NAMING_NSPAWN_LONG_HASH,
        NAMING_V247 = NAMING_V245 | NAMING_BRIDGE_NO_SLOT,
        NAMING_V249 = NAMING_V247 | NAMING_SLOT_FUNCTION_ID | NAMING_16BIT_INDEX | NAMING_REPLACE_STRICTLY,
        NAMING_V250 = NAMING_V249 | NAMING_XEN_VIF,
        NAMING_V251 = NAMING_V250 | NAMING_BRIDGE_MULTIFUNCTION_SLOT,
        NAMING_V252 = NAMING_V251 | NAMING_DEVICETREE_ALIASES,
        NAMING_V253 = NAMING_V252 | NAMING_USB_HOST,
        NAMING_V254 = NAMING_V253 | NAMING_SR_IOV_R,  /* Despite the name, "v254" is NOT the default scheme
                                                       * for systemd version 254. It was added in a follow-up
                                                       * patch later. NAMING_SR_IOV_R is enabled by default in
                                                       * systemd version 255, naming scheme "v255". */
        NAMING_V255 = NAMING_V254 & ~NAMING_BRIDGE_MULTIFUNCTION_SLOT,

        EXTRA_NET_NAMING_SCHEMES

        _NAMING_SCHEME_FLAGS_INVALID = -EINVAL,
} NamingSchemeFlags;

typedef struct NamingScheme {
        const char *name;
        NamingSchemeFlags flags;
} NamingScheme;

const NamingScheme* naming_scheme_from_name(const char *name);
const NamingScheme* naming_scheme(void);

static inline bool naming_scheme_has(NamingSchemeFlags flags) {
        return FLAGS_SET(naming_scheme()->flags, flags);
}

typedef enum NamePolicy {
        NAMEPOLICY_KERNEL,
        NAMEPOLICY_KEEP,
        NAMEPOLICY_DATABASE,
        NAMEPOLICY_ONBOARD,
        NAMEPOLICY_SLOT,
        NAMEPOLICY_PATH,
        NAMEPOLICY_MAC,
        _NAMEPOLICY_MAX,
        _NAMEPOLICY_INVALID = -EINVAL,
} NamePolicy;

const char *name_policy_to_string(NamePolicy p) _const_;
NamePolicy name_policy_from_string(const char *p) _pure_;

const char *alternative_names_policy_to_string(NamePolicy p) _const_;
NamePolicy alternative_names_policy_from_string(const char *p) _pure_;

int device_get_sysattr_int_filtered(sd_device *device, const char *sysattr, int *ret_value);
int device_get_sysattr_unsigned_filtered(sd_device *device, const char *sysattr, unsigned *ret_value);
int device_get_sysattr_bool_filtered(sd_device *device, const char *sysattr);
int sd_device_get_sysattr_value_filtered(sd_device *device, const char *sysattr, const char **ret_value);
