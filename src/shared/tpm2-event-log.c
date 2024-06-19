/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tpm2-event-log.h"

#include "sort-util.h"

typedef struct tpm2_log_event_type_info {
        uint32_t event_type;
        const char *name;
} tpm2_log_event_type_info;

static tpm2_log_event_type_info tpm2_log_event_type_table[] = {
        /* Unfortunately the types are defined all over the place, hence we are not using a dense table
         * here.
         *
         * Keep this sorted by event type, so that we can do bisection! */
        { EV_PREBOOT_CERT,                  "preboot-cert"                  },
        { EV_POST_CODE,                     "post-code"                     },
        { EV_NO_ACTION,                     "no-action"                     },
        { EV_SEPARATOR,                     "separator"                     },
        { EV_ACTION,                        "action"                        },
        { EV_EVENT_TAG,                     "event-tag"                     },
        { EV_S_CRTM_CONTENTS,               "s-crtm-contents"               },
        { EV_S_CRTM_VERSION,                "s-crtm-version"                },
        { EV_CPU_MICROCODE,                 "cpu-microcode"                 },
        { EV_PLATFORM_CONFIG_FLAGS,         "platform-config-flags"         },
        { EV_TABLE_OF_DEVICES,              "table-of-devices"              },
        { EV_COMPACT_HASH,                  "compact-hash"                  },
        { EV_IPL,                           "ipl"                           },
        { EV_IPL_PARTITION_DATA,            "ipl-partition-data"            },
        { EV_NONHOST_CODE,                  "nonhost-code"                  },
        { EV_NONHOST_CONFIG,                "nonhost-config"                },
        { EV_NONHOST_INFO,                  "nonhost-info"                  },
        { EV_OMIT_BOOT_DEVICE_EVENTS,       "omit-boot-device-events"       },
        /* omitting EV_EFI_EVENT_BASE, since its not an event, but just a base value for other events */
        { EV_EFI_VARIABLE_DRIVER_CONFIG,    "efi-variable-driver-config"    },
        { EV_EFI_VARIABLE_BOOT,             "efi-variable-boot"             },
        { EV_EFI_BOOT_SERVICES_APPLICATION, "efi-boot-services-application" },
        { EV_EFI_BOOT_SERVICES_DRIVER,      "efi-boot-services-driver"      },
        { EV_EFI_RUNTIME_SERVICES_DRIVER,   "efi-runtime-services-driver"   },
        { EV_EFI_GPT_EVENT,                 "efi-gpt-event"                 },
        { EV_EFI_ACTION,                    "efi-action"                    },
        { EV_EFI_PLATFORM_FIRMWARE_BLOB,    "efi-platform-firmware-blob"    },
        { EV_EFI_HANDOFF_TABLES,            "efi-handoff-tables"            },
        { EV_EFI_PLATFORM_FIRMWARE_BLOB2,   "efi-platform-firmware-blob2"   },
        { EV_EFI_HANDOFF_TABLES2,           "efi-handoff-tables"            },
        { EV_EFI_VARIABLE_BOOT2,            "efi-variable-boot2"            },
        { EV_EFI_HCRTM_EVENT,               "efi-hcrtm-event"               },
        { EV_EFI_VARIABLE_AUTHORITY,        "efi-variable-authority"        },
        { EV_EFI_SPDM_FIRMWARE_BLOB,        "efi-spdm-firmware-blob"        },
        { EV_EFI_SPDM_FIRMWARE_CONFIG,      "efi-spdm-firmware-config"      },
};

static int tpm2_log_event_type_info_cmp(const tpm2_log_event_type_info *a, const tpm2_log_event_type_info *b) {
        return CMP(ASSERT_PTR(a)->event_type, ASSERT_PTR(b)->event_type);
}

const char* tpm2_log_event_type_to_string(uint32_t type) {

        tpm2_log_event_type_info *found, key = {
                .event_type = type,
        };

        found = typesafe_bsearch(&key, tpm2_log_event_type_table, ELEMENTSOF(tpm2_log_event_type_table), tpm2_log_event_type_info_cmp);

        return found ? found->name : NULL;
}
