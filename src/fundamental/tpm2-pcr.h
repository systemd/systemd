/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro-fundamental.h"

/* The various TPM PCRs we measure into from sd-stub and sd-boot. */

enum {
        /* The following names for PCRs 0…7 are based on the names in the "TCG PC Client Specific Platform
         * Firmware Profile Specification"
         * (https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/) */
        TPM2_PCR_PLATFORM_CODE       = 0,
        TPM2_PCR_PLATFORM_CONFIG     = 1,
        TPM2_PCR_EXTERNAL_CODE       = 2,
        TPM2_PCR_EXTERNAL_CONFIG     = 3,
        TPM2_PCR_BOOT_LOADER_CODE    = 4,
        TPM2_PCR_BOOT_LOADER_CONFIG  = 5,
        TPM2_PCR_HOST_PLATFORM       = 6,
        TPM2_PCR_SECURE_BOOT_POLICY  = 7,

        /* The following names for PCRs 9…15 are based on the "Linux TPM PCR Registry"
        (https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/) */
        TPM2_PCR_KERNEL_INITRD       = 9,
        TPM2_PCR_IMA                 = 10,

        /* systemd: This TPM PCR is where we extend the sd-stub "payloads" into, before using them. i.e. the kernel
         * ELF image, embedded initrd, and so on. In contrast to PCR 4 (which also contains this data, given
         * the whole surrounding PE image is measured into it) this should be reasonably pre-calculatable,
         * because it *only* consists of static data from the kernel PE image. */
        TPM2_PCR_KERNEL_BOOT         = 11,

        /* systemd: This TPM PCR is where sd-stub extends the kernel command line and any passed credentials into. */
        TPM2_PCR_KERNEL_CONFIG       = 12,

        /* systemd: This TPM PCR is where we extend the initrd sysext images into which we pass to the booted kernel */
        TPM2_PCR_SYSEXTS             = 13,
        TPM2_PCR_SHIM_POLICY         = 14,

        /* systemd: This TPM PCR is where we measure the root fs volume key (and maybe /var/'s) if it is split off */
        TPM2_PCR_SYSTEM_IDENTITY     = 15,

        /* As per "TCG PC Client Specific Platform Firmware Profile Specification" again, see above */
        TPM2_PCR_DEBUG               = 16,
        TPM2_PCR_APPLICATION_SUPPORT = 23,
};

/* The tag used for EV_EVENT_TAG event log records covering the boot loader config */
#define LOADER_CONF_EVENT_TAG_ID UINT32_C(0xf5bc582a)

/* The tag used for EV_EVENT_TAG event log records covering DeviceTree blobs */
#define DEVICETREE_ADDON_EVENT_TAG_ID UINT32_C(0x6c46f751)

/* The tag used for EV_EVENT_TAG event log records covering initrd addons */
#define INITRD_ADDON_EVENT_TAG_ID UINT32_C(0x49dffe0f)

/* The tag used for EV_EVENT_TAG event log records covering ucode addons (effectively initrds) */
#define UCODE_ADDON_EVENT_TAG_ID UINT32_C(0xdac08e1a)

/* The tag used for EV_EVENT_TAG event log records covering the selected UKI profile */
#define UKI_PROFILE_EVENT_TAG_ID UINT32_C(0x13aed6db)
