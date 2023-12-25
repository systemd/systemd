/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <math.h>
#include <openssl/evp.h>
#include <sys/file.h>

#include "sd-device.h"

#include "ask-password-api.h"
#include "blockdev-util.h"
#include "build.h"
#include "chase.h"
#include "color-util.h"
#include "conf-files.h"
#include "efi-api.h"
#include "env-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "gpt.h"
#include "hash-funcs.h"
#include "hexdecoct.h"
#include "initrd-util.h"
#include "main-func.h"
#include "mkdir-label.h"
#include "openssl-util.h"
#include "ordered-set.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pcrextend-util.h"
#include "pcrlock-firmware.h"
#include "pehash.h"
#include "pretty-print.h"
#include "proc-cmdline.h"
#include "random-util.h"
#include "recovery-key.h"
#include "sort-util.h"
#include "terminal-util.h"
#include "tpm2-util.h"
#include "unaligned.h"
#include "unit-name.h"
#include "utf8.h"
#include "verbs.h"

static PagerFlags arg_pager_flags = 0;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF|JSON_FORMAT_NEWLINE;
static char **arg_components = NULL;
static uint32_t arg_pcr_mask = 0;
static char *arg_pcrlock_path = NULL;
static bool arg_pcrlock_auto = true;
static bool arg_raw_description = false;
static char *arg_location_start = NULL;
static char *arg_location_end = NULL;
static TPM2_HANDLE arg_nv_index = 0;
static bool arg_recovery_pin = false;
static char *arg_policy_path = NULL;
static bool arg_force = false;

STATIC_DESTRUCTOR_REGISTER(arg_components, strv_freep);
STATIC_DESTRUCTOR_REGISTER(arg_pcrlock_path, freep);
STATIC_DESTRUCTOR_REGISTER(arg_location_start, freep);
STATIC_DESTRUCTOR_REGISTER(arg_location_end, freep);
STATIC_DESTRUCTOR_REGISTER(arg_policy_path, freep);

#define PCRLOCK_SECUREBOOT_POLICY_PATH      "/var/lib/pcrlock.d/240-secureboot-policy.pcrlock.d/generated.pcrlock"
#define PCRLOCK_FIRMWARE_CODE_EARLY_PATH    "/var/lib/pcrlock.d/250-firmware-code-early.pcrlock.d/generated.pcrlock"
#define PCRLOCK_FIRMWARE_CONFIG_EARLY_PATH  "/var/lib/pcrlock.d/250-firmware-config-early.pcrlock.d/generated.pcrlock"
#define PCRLOCK_FIRMWARE_CODE_LATE_PATH     "/var/lib/pcrlock.d/550-firmware-code-late.pcrlock.d/generated.pcrlock"
#define PCRLOCK_FIRMWARE_CONFIG_LATE_PATH   "/var/lib/pcrlock.d/550-firmware-config-late.pcrlock.d/generated.pcrlock"
#define PCRLOCK_GPT_PATH                    "/var/lib/pcrlock.d/600-gpt.pcrlock.d/generated.pcrlock"
#define PCRLOCK_SECUREBOOT_AUTHORITY_PATH   "/var/lib/pcrlock.d/620-secureboot-authority.pcrlock.d/generated.pcrlock"
#define PCRLOCK_KERNEL_CMDLINE_PATH         "/var/lib/pcrlock.d/710-kernel-cmdline.pcrlock/generated.pcrlock"
#define PCRLOCK_KERNEL_INITRD_PATH          "/var/lib/pcrlock.d/720-kernel-initrd.pcrlock/generated.pcrlock"
#define PCRLOCK_MACHINE_ID_PATH             "/var/lib/pcrlock.d/820-machine-id.pcrlock"
#define PCRLOCK_ROOT_FILE_SYSTEM_PATH       "/var/lib/pcrlock.d/830-root-file-system.pcrlock"
#define PCRLOCK_FILE_SYSTEM_PATH_PREFIX     "/var/lib/pcrlock.d/840-file-system-"

/* The default set of PCRs to lock to */
#define DEFAULT_PCR_MASK                                     \
        ((UINT32_C(1) << TPM2_PCR_PLATFORM_CODE) |           \
         (UINT32_C(1) << TPM2_PCR_PLATFORM_CONFIG) |         \
         (UINT32_C(1) << TPM2_PCR_EXTERNAL_CODE) |           \
         (UINT32_C(1) << TPM2_PCR_EXTERNAL_CONFIG) |         \
         (UINT32_C(1) << TPM2_PCR_BOOT_LOADER_CODE) |        \
         (UINT32_C(1) << TPM2_PCR_BOOT_LOADER_CONFIG) |      \
         (UINT32_C(1) << TPM2_PCR_SECURE_BOOT_POLICY) |      \
         (UINT32_C(1) << TPM2_PCR_KERNEL_BOOT) |             \
         (UINT32_C(1) << TPM2_PCR_KERNEL_CONFIG) |           \
         (UINT32_C(1) << TPM2_PCR_SYSEXTS) |                 \
         (UINT32_C(1) << TPM2_PCR_SHIM_POLICY) |             \
         (UINT32_C(1) << TPM2_PCR_SYSTEM_IDENTITY))

typedef struct EventLogRecordBank EventLogRecordBank;
typedef struct EventLogRecord EventLogRecord;
typedef struct EventLogRegisterBank EventLogRegisterBank;
typedef struct EventLogRegister EventLogRegister;
typedef struct EventLogComponentVariant EventLogComponentVariant;
typedef struct EventLogComponent EventLogComponent;
typedef struct EventLog EventLog;

struct EventLogRecordBank {
        uint16_t algorithm;
        TPM2B_DIGEST hash;
        LIST_FIELDS(EventLogRecordBank, banks);
};

typedef enum EventPayloadValid {
        EVENT_PAYLOAD_VALID_YES,
        EVENT_PAYLOAD_VALID_NO,
        EVENT_PAYLOAD_VALID_DONT_KNOW,
        _EVENT_PAYLOAD_VALID_MAX,
        _EVENT_PAYLOAD_VALID_INVALID = -EINVAL,
} EventPayloadValid;

struct EventLogRecord {
        EventLog *event_log;
        uint32_t pcr;

        const char *source;
        char *description;

        /* Data for firmware events (i.e. "TCG PC Client Platform Firmware Profile Specification" events) */
        uint32_t firmware_event_type;
        void *firmware_payload;
        size_t firmware_payload_size;

        /* Data for userspace events (i.e. those generated by systemd in userspace */
        Tpm2UserspaceEventType userspace_event_type;
        JsonVariant *userspace_content;

        /* Validation result for the event payload itself, if the record contains enough information to validate the hash */
        EventPayloadValid event_payload_valid;

        /* If this record matches an variant of one of our defined components */
        EventLogComponentVariant **mapped;
        size_t n_mapped;

        /* If this record is part of an EventLogComponentVariant */
        EventLogComponentVariant *owning_component_variant;

        LIST_HEAD(EventLogRecordBank, banks);
};

#define EVENT_LOG_RECORD_IS_FIRMWARE(record) ((record)->firmware_event_type != UINT32_MAX)
#define EVENT_LOG_RECORD_IS_USERSPACE(record) ((record)->userspace_event_type >= 0)

struct EventLogRegisterBank {
        TPM2B_DIGEST observed;
        TPM2B_DIGEST calculated;
};

struct EventLogRegister {
        char *color;
        unsigned n_measurements;
        bool fully_recognized; /* true if all measurements in this register have been recognized to match components */
        EventLogRegisterBank *banks;
};

struct EventLogComponentVariant {
        EventLogComponent *component;

        char *id;
        char *path;

        EventLogRecord **records;
        size_t n_records;
};

struct EventLogComponent {
        char *id;

        EventLogComponentVariant **variants;
        size_t n_variants;
};

struct EventLog {
        EventLogRecord **records;
        size_t n_records;

        uint16_t *algorithms;
        size_t n_algorithms;
        bool algorithms_locked; /* if algorithms where set explicitly by user, and we should not determine them automatically */

        const EVP_MD **mds;

        /* The hash algorithm which we focus on for matching up components */
        uint16_t primary_algorithm;

        uint8_t startup_locality;
        bool startup_locality_found;

        EventLogRegister registers[TPM2_PCRS_MAX];

        EventLogComponent **components;
        size_t n_components;

        /* Number of components which we couldn't find in the event log */
        size_t n_missing_components;

        /* PCRs mask indicating all PCRs touched by unrecognized components */
        uint32_t missing_component_pcrs;
};

static EventLogRecordBank *event_log_record_bank_free(EventLogRecordBank *bank) {
        return mfree(bank);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(EventLogRecordBank*, event_log_record_bank_free);

static EventLogRecord *event_log_record_free(EventLogRecord *record) {
        EventLogRecordBank *bank;

        if (!record)
                return NULL;

        free(record->description);
        free(record->firmware_payload);
        json_variant_unref(record->userspace_content);

        while ((bank = LIST_POP(banks, record->banks)))
                event_log_record_bank_free(bank);

        free(record->mapped);

        return mfree(record);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(EventLogRecord*, event_log_record_free);

static void event_log_register_done(EventLog *el, EventLogRegister *reg) {
        assert(reg);

        free(reg->color);
        free(reg->banks);
}

static EventLogComponentVariant* event_log_component_variant_free(EventLogComponentVariant *variant) {
        if (!variant)
                return NULL;

        free(variant->id);
        free(variant->path);

        FOREACH_ARRAY(record, variant->records, variant->n_records)
                event_log_record_free(*record);

        free(variant->records);

        return mfree(variant);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(EventLogComponentVariant*, event_log_component_variant_free);

static EventLogComponent* event_log_component_free(EventLogComponent *component) {
        if (!component)
                return NULL;

        FOREACH_ARRAY(variant, component->variants, component->n_variants)
                event_log_component_variant_free(*variant);
        free(component->variants);

        free(component->id);

        return mfree(component);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(EventLogComponent*, event_log_component_free);

static EventLog* event_log_free(EventLog *el) {
        if (!el)
                return NULL;

        FOREACH_ARRAY(p, el->registers, TPM2_PCRS_MAX)
                event_log_register_done(el, p);

        FOREACH_ARRAY(rr, el->records, el->n_records)
                event_log_record_free(*rr);
        free(el->records);

        FOREACH_ARRAY(c, el->components, el->n_components)
                event_log_component_free(*c);
        free(el->components);

        free(el->algorithms);
        free(el->mds);

        return mfree(el);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(EventLog*, event_log_free);

static EventLogRecord* event_log_record_new(EventLog *el) {
        EventLogRecord *record;

        record = new(EventLogRecord, 1);
        if (!record)
                return NULL;

        *record = (EventLogRecord) {
                .event_log = el,
                .firmware_event_type = UINT32_MAX,
                .userspace_event_type = _TPM2_USERSPACE_EVENT_TYPE_INVALID,
                .event_payload_valid = _EVENT_PAYLOAD_VALID_INVALID,
        };

        return record;
}

static int event_log_add_record(
                EventLog *el,
                EventLogRecord **ret) {

        _cleanup_(event_log_record_freep) EventLogRecord *record = NULL;

        assert(el);

        if (!GREEDY_REALLOC(el->records, el->n_records+1))
                return -ENOMEM;

        record = event_log_record_new(el);
        if (!record)
                return -ENOMEM;

        el->records[el->n_records++] = record;

        if (ret)
                *ret = record;

        TAKE_PTR(record);

        return 0;
}

static int event_log_add_algorithm(EventLog *el, uint16_t alg) {
        assert(el);

        if (el->algorithms_locked) /* algorithms configured via env var, don't add any further automatically */
                return 0;

        if (typesafe_bsearch(&alg, el->algorithms, el->n_algorithms, cmp_uint16))
                return 0;

        if (!GREEDY_REALLOC(el->algorithms, el->n_algorithms+1))
                return -ENOMEM;

        el->algorithms[el->n_algorithms++] = alg;

        typesafe_qsort(el->algorithms, el->n_algorithms, cmp_uint16);

        return 1;
}

static int event_log_add_algorithms_from_environment(EventLog *el) {
        const char *e;
        int r;

        assert(el);

        e = secure_getenv("SYSTEMD_TPM2_HASH_ALGORITHMS");
        if (!e)
                return 0;

        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&e, &word, ":", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = tpm2_hash_alg_from_string(word);
                if (r < 0)
                        return log_error_errno(r, "Unknown hash algorithm '%s'.", word);

                r = event_log_add_algorithm(el, r);
                if (r < 0)
                        return log_error_errno(r, "Failed to add hash algorithm '%s'.", word);
        }

        if (el->n_algorithms > 0)
                el->algorithms_locked = true;

        return 0;
}

static EventLogRecordBank *event_log_record_find_bank(
                const EventLogRecord *record,
                uint16_t alg) {

        assert(record);

        LIST_FOREACH(banks, i, record->banks)
                if (i->algorithm == alg)
                        return i;

        return NULL;
}

static int event_log_record_add_bank(
                EventLogRecord *record,
                uint16_t algorithm,
                const void *hash,
                size_t hash_size,
                EventLogRecordBank **ret) {

        _cleanup_(event_log_record_bank_freep) EventLogRecordBank *bank = NULL;
        _cleanup_free_ void *h = NULL;

        assert(record);
        assert(hash || hash_size == 0);

        if (event_log_record_find_bank(record, algorithm))
                return -EEXIST;

        if (hash_size > sizeof_field(TPM2B_DIGEST, buffer))
                return -E2BIG;

        h = memdup(hash, hash_size);
        if (!h)
                return -ENOMEM;

        bank = new(EventLogRecordBank, 1);
        if (!bank)
                return -ENOMEM;

        *bank = (EventLogRecordBank) {
                .algorithm = algorithm,
                .hash = TPM2B_DIGEST_MAKE(hash, hash_size),
        };

        LIST_PREPEND(banks, record->banks, bank);

        if (ret)
                *ret = bank;

        TAKE_PTR(bank);

        return 0;
}

static bool event_log_record_is_stub(EventLogRecord *rec) {
        assert(rec);

        /* Recognizes the special EV_IPL events systemd-stub generates. Since EV_IPL can be used by almost
         * anything, we'll check for the PCR values, to see if it's one of ours. */

        if (rec->firmware_event_type != EV_IPL)
                return false;

        if (!EVENT_LOG_RECORD_IS_FIRMWARE(rec))
                return false;

        if (!IN_SET(rec->pcr,
                    TPM2_PCR_KERNEL_BOOT,        /* 11 */
                    TPM2_PCR_KERNEL_CONFIG,      /* 12 */
                    TPM2_PCR_SYSEXTS))           /* 13 */
                return false;

        return true;
}

static int event_log_record_parse_variable_data(
                EventLogRecord *rec,
                sd_id128_t *ret_variable_uuid,
                char **ret_variable_name) {

        _cleanup_free_ char16_t *p16 = NULL;
        _cleanup_free_ char *p = NULL;

        assert(rec);
        assert(ret_variable_uuid);
        assert(ret_variable_name);

        if (rec->firmware_payload_size < sizeof(UEFI_VARIABLE_DATA))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "EFI variable field too short.");

        const UEFI_VARIABLE_DATA *vdata = rec->firmware_payload;

        if (vdata->unicodeNameLength > (SIZE_MAX - offsetof(UEFI_VARIABLE_DATA, unicodeNameLength)) / 2)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Unicode name length too large.");

        size_t m = offsetof(UEFI_VARIABLE_DATA, unicodeName) + vdata->unicodeNameLength * 2;

        if (vdata->variableDataLength > SIZE_MAX - m)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Oversize EFI variable data size.");

        if (rec->firmware_payload_size != m + vdata->variableDataLength)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "EFI variable data has wrong size.");

        p16 = memdup(vdata->unicodeName, vdata->unicodeNameLength * 2); /* Copy out, to align properly */
        if (!p16)
                return log_oom_debug();

        p = utf16_to_utf8(p16, vdata->unicodeNameLength * 2);
        if (!p)
                return log_oom_debug();

        if (!string_is_safe(p))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "Unsafe EFI variable string in record.");

        *ret_variable_uuid = efi_guid_to_id128(vdata->variableName);
        *ret_variable_name = TAKE_PTR(p);

        return 0;
}

static int event_log_record_extract_firmware_description(EventLogRecord *rec) {
        _cleanup_free_ char *fallback = NULL;
        int r;

        assert(rec);

        if (!EVENT_LOG_RECORD_IS_FIRMWARE(rec))
                return 0;

        if (arg_raw_description)
                goto catchall;

        switch (rec->firmware_event_type) {

        case EV_EFI_VARIABLE_DRIVER_CONFIG:
        case EV_EFI_VARIABLE_BOOT:
        case EV_EFI_VARIABLE_BOOT2:
        case EV_EFI_VARIABLE_AUTHORITY: {
                _cleanup_free_ char *p = NULL;
                sd_id128_t uuid;

                r = event_log_record_parse_variable_data(rec, &uuid, &p);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_warning_errno(r, "EFI variable data invalid, ignoring.");
                        goto invalid;
                }

                if (asprintf(&rec->description, "%s: %s-" SD_ID128_UUID_FORMAT_STR,
                             rec->firmware_event_type == EV_EFI_VARIABLE_AUTHORITY ? "Authority" : "Variable",
                             p,
                             SD_ID128_FORMAT_VAL(uuid)) < 0)
                        return log_oom();

                return 1;
        }

        case EV_SEPARATOR: {
                if (rec->firmware_payload_size != sizeof(uint32_t)) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "EFI separator field has wrong size, ignoring.");
                        goto invalid;
                }

                uint32_t val = unaligned_read_ne32(rec->firmware_payload);

                switch (val) {

                case 0:
                case UINT32_C(0xffffffff):
                        (void) asprintf(&rec->description, "Separator: Success (0x%02" PRIx32 ")", val);
                        break;

                case 1:
                        rec->description = strdup("Separator: Error (0x01)");
                        break;

                default:
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Unexpected separator payload %" PRIu32 ".", val);
                        goto invalid;
                }

                if (!rec->description)
                        return log_oom();

                return 1;
        }

        case EV_EFI_ACTION: {
                _cleanup_free_ char *d = NULL;

                r = make_cstring(rec->firmware_payload, rec->firmware_payload_size, MAKE_CSTRING_ALLOW_TRAILING_NUL, &d);
                if (r < 0)
                        return log_error_errno(r, "Failed to make C string from EFI action string: %m");

                if (!string_is_safe(d)) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Unsafe EFI action string in record, ignoring.");
                        goto invalid;
                }

                rec->description = strjoin("Action: ", d);
                if (!rec->description)
                        return log_oom();
                return 1;
        }

        case EV_EFI_GPT_EVENT: {
                if (rec->firmware_payload_size < sizeof(GptHeader)) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "GPT measurement too short, ignoring.");
                        goto invalid;
                }

                const GptHeader *h = rec->firmware_payload;

                if (!gpt_header_has_signature(h)) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "GPT measurement does not cover a GPT partition table header, ignoring.");
                        goto invalid;
                }

                if (asprintf(&rec->description, "GPT: disk " SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(efi_guid_to_id128(h->disk_guid))) < 0)
                        return log_oom();

                return 1;
        }

        case EV_IPL: {
                _cleanup_free_ char *d = NULL;

                /* EV_IPL can be anything, only try to parse the description on PCRs we "own" */
                if (!event_log_record_is_stub(rec))
                        break;

                /* sd-stub always sets a description string as text for these */

                d = utf16_to_utf8(rec->firmware_payload, rec->firmware_payload_size);
                if (!d)
                        return log_oom();

                if (string_has_cc(d, NULL)) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Unsafe EFI action string in record, ignoring.");
                        goto invalid;
                }

                rec->description = strjoin("String: ", d);
                if (!rec->description)
                        return log_oom();

                return 1;
        }

        case EV_EVENT_TAG: {
                TCG_PCClientTaggedEvent *tag = rec->firmware_payload;
                size_t left = rec->firmware_payload_size;

                if (left == 0) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Empty tagged PC client event, ignoring.");
                        goto invalid;
                }

                for (;;) {
                        uint64_t m;

                        if (left < offsetof(TCG_PCClientTaggedEvent, taggedEventData)) {
                                log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Tagged PC client event too short, ignoring.");
                                goto invalid;
                        }

                        m = offsetof(TCG_PCClientTaggedEvent, taggedEventData) + (uint64_t) tag->taggedEventDataSize;
                        if (left < m) {
                                log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Tagged PC client event data too short, ignoring.");
                                goto invalid;
                        }

                        switch (tag->taggedEventID) {

                        /* Linux kernel's own measurements: */
                        case INITRD_EVENT_TAG_ID:
                                /* The tagged event payload is just a constant string, hence don't show it */
                                if (!strextend_with_separator(&rec->description, ", ", "Linux: initrd"))
                                        return log_oom();
                                break;

                        case LOAD_OPTIONS_EVENT_TAG_ID:
                                /* As above. */
                                if (!strextend_with_separator(&rec->description, ", ", "Linux: kernel command line"))
                                        return log_oom();
                                break;

                        /* systemd's measurements: */
                        case LOADER_CONF_EVENT_TAG_ID:
                                /* As above. */
                                if (!strextend_with_separator(&rec->description, ", ", "systemd-boot: loader.conf"))
                                        return log_oom();
                                break;

                        case DEVICETREE_ADDON_EVENT_TAG_ID: {
                                _cleanup_free_ char *raw = NULL, *s = NULL;

                                raw = utf16_to_utf8((const char16_t*) tag->taggedEventData, tag->taggedEventDataSize);
                                if (!raw)
                                        return log_oom();

                                s = cescape(raw);
                                if (!s)
                                        return log_oom();

                                r = strextendf_with_separator(&rec->description, ", ", "systemd-stub: devicetree addon %s", s);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to format EV_EVENT_TAG description string: %m");
                                break;
                        }

                        default: {
                                _cleanup_free_ char *s = NULL;

                                s = cescape_length((char*) tag->taggedEventData, tag->taggedEventDataSize);
                                if (!s)
                                        return log_oom();

                                r = strextendf_with_separator(&rec->description, ", ", "Tag 0x%" PRIx32 ": %s", tag->taggedEventID, s);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to format EV_EVENT_TAG description string: %m");

                                break;
                        }}

                        tag = (TCG_PCClientTaggedEvent*) ((uint8_t*) tag + m);
                        left -= m;

                        if (left == 0)
                                break;
                }

                return 1;
        }

        case EV_EFI_PLATFORM_FIRMWARE_BLOB: {
                const UEFI_PLATFORM_FIRMWARE_BLOB *blob;
                if (rec->firmware_payload_size != sizeof(UEFI_PLATFORM_FIRMWARE_BLOB)) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "EV_EFI_PLATFORM_FIRMWARE_BLOB of wrong size, ignoring.");
                        goto invalid;
                }

                blob = rec->firmware_payload;
                if (asprintf(&rec->description, "Blob: %s @ 0x%" PRIx64, FORMAT_BYTES(blob->blobLength), blob->blobBase) < 0)
                        return log_oom();

                return 1;
        }

        case EV_EFI_BOOT_SERVICES_APPLICATION:
        case EV_EFI_BOOT_SERVICES_DRIVER:
        case EV_EFI_RUNTIME_SERVICES_DRIVER: {
                const UEFI_IMAGE_LOAD_EVENT *load;
                _cleanup_free_ char *fn = NULL;
                bool end = false;

                if (rec->firmware_payload_size < offsetof(UEFI_IMAGE_LOAD_EVENT, devicePath)) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Device path too short, ignoring.");
                        goto invalid;
                }

                load = rec->firmware_payload;
                if (load->lengthOfDevicePath !=
                    rec->firmware_payload_size - offsetof(UEFI_IMAGE_LOAD_EVENT, devicePath)) {
                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Device path size does not match, ignoring.");
                        goto invalid;
                }

                const packed_EFI_DEVICE_PATH *dp = (const packed_EFI_DEVICE_PATH*) load->devicePath;
                size_t left = load->lengthOfDevicePath;

                for (;;) {
                        if (left == 0) {
                                if (!end) {
                                        log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Garbage after device path end, ignoring.");
                                        goto invalid;
                                }

                                break;
                        }

                        if (end) {
                                log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Garbage after device path end, ignoring.");
                                goto invalid;
                        }

                        if (left < offsetof(packed_EFI_DEVICE_PATH, path) || left < dp->length) {
                                log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Device path element too short, ignoring.");
                                goto invalid;
                        }

                        if (dp->type == 4 && dp->subType == 4) {
                                /* Filename, store the last node of this type as description, it should contain the file name */

                                free(fn);
                                fn = utf16_to_utf8((void*) dp->path, dp->length - offsetof(packed_EFI_DEVICE_PATH, path));
                                if (!fn)
                                        return log_oom();

                        } else if (dp->type == 0x7F && dp->subType == 0xFF)
                                /* End of Hardware Device Path */
                                end = true;
                        else
                                log_debug("Ignoring device path element type=0x%02x subtype=0x%02x", dp->type, dp->subType);

                        left -= dp->length;
                        dp = (packed_EFI_DEVICE_PATH*) ((uint8_t*) dp + dp->length);
                }

                if (fn) {
                        rec->description = strjoin("File: ", fn);
                        if (!rec->description)
                                return log_oom();

                        return 1;
                }

                break;
        }}

catchall:
        /* Catchall: show binary data */
        fallback = cescape_length(rec->firmware_payload, rec->firmware_payload_size);
        if (!fallback)
                return log_oom();

        rec->description = strjoin("Raw: ", fallback);
        if (!rec->description)
                return log_oom();
        return 1;


invalid:
        /* Mark the payload as invalid, so that we do not bother parsing/validating it any further */
        rec->event_payload_valid = EVENT_PAYLOAD_VALID_NO;
        return 0;
}

static int event_log_add_algorithms_from_record(EventLog *el, EventLogRecord *record) {
        int r;

        assert(el);
        assert(record);

        if (el->algorithms_locked)
                return 0;

        LIST_FOREACH(banks, i, record->banks) {
                r = event_log_add_algorithm(el, i->algorithm);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int event_log_load_firmware(EventLog *el) {
        const TCG_EfiSpecIdEventAlgorithmSize *algorithms;
        size_t bufsize = 0, n_algorithms = 0, left = 0;
        _cleanup_free_ void *buf = NULL;
        const TCG_PCR_EVENT2 *event;
        const char *path;
        int r;

        assert(el);

        path = tpm2_firmware_log_path();

        r = read_full_file(path, (char**) &buf, &bufsize);
        if (r < 0)
                return log_error_errno(r, "Failed to open TPM2 event log '%s': %m", path);

        if (bufsize == 0) {
                /* Sometimes it's useful to invoke things with SYSTEMD_MEASURE_LOG_FIRMWARE=/dev/null, let's allow that, and proceed */
                log_warning("Empty firmware event log file, not loading.");
                return 0;
        }

        r = validate_firmware_header(buf, bufsize, &algorithms, &n_algorithms, &event, &left);
        if (r < 0)
                return r;

        for (const TCG_PCR_EVENT2 *next_event = NULL;; event = next_event) {
                EventLogRecord *record = NULL;
                const void *payload;
                size_t payload_size;

                r = validate_firmware_event(
                                event,
                                left,
                                algorithms,
                                n_algorithms,
                                &next_event,
                                &left,
                                &payload,
                                &payload_size);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (event->eventType == EV_NO_ACTION &&
                    event->pcrIndex == 0 &&
                    payload_size == 17 &&
                    memcmp(payload, "StartupLocality", sizeof("StartupLocality")) == 0) {
                        if (el->startup_locality_found)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "StartupLocality event found twice!");

                        el->startup_locality = ((const uint8_t*) payload)[sizeof("StartupLocality")];
                        el->startup_locality_found = true;
                        log_debug("Found StartupLocality event: %u", el->startup_locality);
                        continue;
                }

                if (event->eventType == EV_NO_ACTION) { /* Ignore pseudo events, that don't result in a measurement */
                        log_debug("Skipping NO_ACTION event.");
                        continue;
                }

                r = event_log_add_record(el, &record);
                if (r < 0)
                        return log_error_errno(r, "Failed to add record to event log: %m");

                record->pcr = event->pcrIndex;
                record->source = path;
                record->firmware_event_type = event->eventType;
                record->firmware_payload = memdup(payload, payload_size);
                if (!record->firmware_payload)
                        return log_oom();
                record->firmware_payload_size = payload_size;

                const void *ha, *ha_next = NULL;
                ha = (const uint8_t*) event + offsetof(TCG_PCR_EVENT2, digests.digests);
                assert(event->digests.count == n_algorithms);

                for (size_t i = 0; i < n_algorithms; i++, ha = ha_next) {
                        ha_next = (const uint8_t*) ha + offsetof(TPMT_HA, digest) + algorithms[i].digestSize;

                        /* The TPMT_HA is not aligned in the record, hence read the hashAlg field via an unaligned read */
                        assert_cc(__builtin_types_compatible_p(uint16_t, typeof(TPMI_ALG_HASH)));
                        uint16_t hash_alg = unaligned_read_ne16((const uint8_t*) ha + offsetof(TPMT_HA, hashAlg));

                        if (hash_alg != algorithms[i].algorithmId)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Hash algorithms in event log record don't match log.");

                        if (!tpm2_hash_alg_to_string(algorithms[i].algorithmId))
                                continue;

                        r = event_log_record_add_bank(
                                        record,
                                        algorithms[i].algorithmId,
                                        (const uint8_t*) ha + offsetof(TPMT_HA, digest),
                                        algorithms[i].digestSize,
                                        /* ret= */ NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add bank to event log record: %m");
                }

                /* Try to extract a descriptive text */
                r = event_log_record_extract_firmware_description(record);
                if (r < 0)
                        return r;

                r = event_log_add_algorithms_from_record(el, record);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int event_log_record_parse_json(EventLogRecord *record, JsonVariant *j) {
        const char *rectype = NULL;
        JsonVariant *x, *k;
        uint64_t u;
        int r;

        assert(record);
        assert(j);

        if (!json_variant_is_object(j))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "record object is not an object.");

        x = json_variant_by_key(j, "pcr");
        if (!x)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'pcr' field missing from TPM measurement log file entry.");
        if (!json_variant_is_unsigned(x))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'pcr' field is not an integer.");

        u = json_variant_unsigned(x);
        if (u >= TPM2_PCRS_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'pcr' field is out of range.");
        record->pcr = json_variant_unsigned(x);

        x = json_variant_by_key(j, "digests");
        if (!x)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'digests' field missing from TPM measurement log file entry.");
        if (!json_variant_is_array(x))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'digests' field is not an array.");

        JSON_VARIANT_ARRAY_FOREACH(k, x) {
                _cleanup_free_ void *hash = NULL;
                size_t hash_size;
                JsonVariant *a, *h;
                int na;

                a = json_variant_by_key(k, "hashAlg");
                if (!a)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'digests' field element lacks 'hashAlg' field.");
                if (!json_variant_is_string(a))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'hashAlg' field is not a string.");

                na = tpm2_hash_alg_from_string(json_variant_string(a));
                if (na < 0) {
                        log_debug_errno(na, "Unsupported hash '%s' in userspace event log, ignoring: %m", json_variant_string(a));
                        continue;
                }

                h = json_variant_by_key(k, "digest");
                if (!h)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'digests' field lacks 'digest' field");

                r = json_variant_unhex(h, &hash, &hash_size);
                if (r < 0)
                        return log_error_errno(r, "Failed to decode digest: %m");

                r = event_log_record_add_bank(
                                record,
                                na,
                                hash,
                                hash_size,
                                /* ret= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add bank to event log record: %m");
        }

        x = json_variant_by_key(j, "content_type");
        if (!x)
                log_debug("'content_type' missing from TPM measurement log file entry, ignoring.");
        else {
                if (!json_variant_is_string(x))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'content_type' field is not a string.");

                rectype = json_variant_string(x);
        }

        if (streq_ptr(rectype, "systemd")) {
                JsonVariant *y;

                x = json_variant_by_key(j, "content");
                if (!x)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'content' field missing from TPM measurement log file entry.");
                if (!json_variant_is_object(x))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'content' sub-object is not an object.");

                y = json_variant_by_key(x, "string");
                if (y) {
                        if (!json_variant_is_string(y))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'string' field is not a string.");

                        r = free_and_strdup_warn(&record->description, json_variant_string(y));
                        if (r < 0)
                                return r;
                }

                y = json_variant_by_key(x, "eventType");
                if (y) {
                        if (!json_variant_is_string(y))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'eventType' field is not a string.");

                        record->userspace_event_type = tpm2_userspace_event_type_from_string(json_variant_string(y));
                        if (record->userspace_event_type < 0)
                                log_debug_errno(record->userspace_event_type, "Unknown userspace event type '%s', ignoring.", json_variant_string(y));
                }

                json_variant_unref(record->userspace_content);
                record->userspace_content = json_variant_ref(x);
        }

        return 0;
}

static int event_log_load_userspace(EventLog *el) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *b = NULL;
        bool beginning = true;
        const char *path;
        size_t bn = 0;
        int r;

        assert(el);

        path = tpm2_userspace_log_path();

        f = fopen(path, "re");
        if (!f) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to open userspace TPM measurement log file: %m");

                return 0;
        }

        if (flock(fileno(f), LOCK_SH) < 0)
                return log_error_errno(errno, "Failed to lock userspace TPM measurement log file: %m");

        for (;;) {
                _cleanup_(json_variant_unrefp) JsonVariant *j = NULL;
                EventLogRecord *record;
                int ch;

                ch = fgetc(f);
                if (ch == EOF) {
                        if (ferror(f))
                                return log_error_errno(errno, "Failed to read local TPM measurement log file: %m");

                        if (beginning)
                                break;
                } else if (ch != 0x1EU) {
                        if (!GREEDY_REALLOC(b, bn + 2))
                                return log_oom();

                        b[bn++] = (char) ch;
                        continue;
                }

                if (beginning) {
                        beginning = false;
                        continue;
                }

                if (!GREEDY_REALLOC(b, bn + 1))
                        return log_oom();

                b[bn] = 0; /* Turn it into a string */

                if (memchr(b, 0, bn)) {
                        log_warning("Found record with embedded NUL byte, skipping.");
                        continue;
                }

                r = json_parse(b, 0, &j, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse local TPM measurement log file: %m");

                r = event_log_add_record(el, &record);
                if (r < 0)
                        return log_error_errno(r, "Failed to add record to event log: %m");

                record->source = path;

                r = event_log_record_parse_json(record, j);
                if (r < 0)
                        return r;

                r = event_log_add_algorithms_from_record(el, record);
                if (r < 0)
                        return r;

                if (ch == EOF)
                        break;

                b = mfree(b);
                bn = 0;
        }

        return 0;
}

static EventLog *event_log_new(void) {
        _cleanup_(event_log_freep) EventLog *el = NULL;

        el = new(EventLog, 1);
        if (!el)
                return NULL;

        *el = (EventLog) {
                .primary_algorithm = UINT16_MAX,
        };

        return TAKE_PTR(el);
}

static int event_log_load(EventLog *el) {
        int r;

        assert(el);

        r = event_log_load_firmware(el);
        if (r < 0)
                return r;

        r = event_log_load_userspace(el);
        if (r < 0)
                return r;

        return 0;
}

static int event_log_read_pcrs(EventLog *el) {
        _cleanup_(tpm2_context_unrefp) Tpm2Context *tc = NULL;
        int r;

        assert(el);

        r = tpm2_context_new(NULL, &tc);
        if (r < 0)
                return r;

        FOREACH_ARRAY(rr, el->registers, TPM2_PCRS_MAX) {
                if (rr->banks)
                        continue;

                rr->banks = new0(EventLogRegisterBank, el->n_algorithms);
                if (!rr->banks)
                        return log_oom();
        }

        for (size_t a = 0; a < el->n_algorithms; a++) {
                _cleanup_free_ Tpm2PCRValue *pcr_values = NULL;
                size_t n_pcr_values;
                TPML_PCR_SELECTION selection;

                tpm2_tpml_pcr_selection_from_mask(TPM2_PCRS_MASK, el->algorithms[a], &selection);
                r = tpm2_pcr_read(tc, &selection, &pcr_values, &n_pcr_values);
                if (r < 0)
                        return r;

                FOREACH_ARRAY(v, pcr_values, n_pcr_values) {
                        assert(v->hash == el->algorithms[a]);
                        el->registers[v->index].banks[a].observed = v->value;
                }
        }

        return 0;
}

static void event_log_initial_pcr_state(EventLog *el, uint32_t pcr, size_t size, TPM2B_DIGEST *ret) {
        assert(el);
        assert(pcr < TPM2_PCRS_MAX);
        assert(size > 0);
        assert(size <= sizeof_field(TPM2B_DIGEST, buffer));
        assert(ret);

        ret->size = size;

        switch (pcr) {

        case 0:
                memzero(ret->buffer, ret->size-1);
                ((uint8_t*) ret->buffer)[ret->size-1] = el->startup_locality_found ? el->startup_locality : 0;
                break;

        case 1 ... 16:
        case 23:
                memzero(ret->buffer, ret->size);
                break;

        case 17 ... 22:
                memset(ret->buffer, 0xffu, ret->size);
                break;

        default:
                assert_not_reached();
        }
}

static int event_log_calculate_pcrs(EventLog *el) {
        assert(el);

        /* Iterates through the event log an calculates the expected hash values based on all listed records */

        assert(!el->mds);
        el->mds = new(const EVP_MD*, el->n_algorithms);
        if (!el->mds)
                return log_oom();

        for (size_t i = 0; i < el->n_algorithms; i++) {
                const EVP_MD *md;
                const char *a;

                assert_se(a = tpm2_hash_alg_to_string(el->algorithms[i]));
                assert_se(md = EVP_get_digestbyname(a));

                el->mds[i] = md;
        }

        for (uint32_t pcr = 0; pcr < TPM2_PCRS_MAX; pcr++)
                for (size_t i = 0; i < el->n_algorithms; i++) {
                        EventLogRegisterBank *b = el->registers[pcr].banks + i;
                        event_log_initial_pcr_state(el, pcr, EVP_MD_size(el->mds[i]), &b->calculated);
                }

        FOREACH_ARRAY(rr, el->records, el->n_records) {
                EventLogRegister *reg = el->registers + (*rr)->pcr;

                for (size_t i = 0; i < el->n_algorithms; i++) {
                        const char *n = tpm2_hash_alg_to_string(el->algorithms[i]);
                        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *mc = NULL;
                        EventLogRegisterBank *reg_b;
                        EventLogRecordBank *rec_b;
                        unsigned sz;

                        rec_b = event_log_record_find_bank(*rr, el->algorithms[i]);
                        if (!rec_b) {
                                log_warning_errno(SYNTHETIC_ERRNO(ENXIO), "Record with missing bank '%s', ignoring.", n);
                                continue;
                        }

                        reg_b = reg->banks + i;

                        mc = EVP_MD_CTX_new();
                        if (!mc)
                                return log_oom();

                        if (EVP_DigestInit_ex(mc, el->mds[i], NULL) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to initialize %s message digest context.", n);

                        if (EVP_DigestUpdate(mc, reg_b->calculated.buffer, reg_b->calculated.size) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

                        if (EVP_DigestUpdate(mc, rec_b->hash.buffer, rec_b->hash.size) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to run digest.");

                        if (EVP_DigestFinal_ex(mc, reg_b->calculated.buffer, &sz) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to finalize hash context.");

                        assert(sz == reg_b->calculated.size);
                }

                reg->n_measurements++;
        }

        return 0;
}

static int event_log_record_validate_hash_firmware(
                EventLogRecord *record,
                EventLogRecordBank *bank,
                const EVP_MD *md) {

        _cleanup_free_ void *hdata_alternative = NULL;
        size_t hsz, hsz_alternative = 0;
        bool strict = false;
        const void *hdata;

        assert(record);
        assert(bank);
        assert(md);

        if (!EVENT_LOG_RECORD_IS_FIRMWARE(record))
                return 0;

        switch (record->firmware_event_type) {

        case EV_EFI_ACTION:
        case EV_EFI_GPT_EVENT:
        case EV_EFI_VARIABLE_BOOT2:
        case EV_EFI_VARIABLE_DRIVER_CONFIG:
        case EV_EFI_VARIABLE_AUTHORITY:
        case EV_SEPARATOR:
        case EV_S_CRTM_VERSION:
                /* Here the extended hash value is the hash value of the event payload. Note that
                 * EV_PLATFORM_CONFIG_FLAGS (according to the TCG PC Client Platform Firmware Profile
                 * Specification) is also supposed to be like this. But ovmf doesn't follow this requirement,
                 * hence be lenient on that one, and don't include it here. */
                hdata = record->firmware_payload;
                hsz = record->firmware_payload_size;
                strict = true;
                break;

        case EV_EFI_VARIABLE_BOOT: {
                const UEFI_VARIABLE_DATA *vdata = record->firmware_payload;
                size_t skip;

                /* Here the extended hash value is the hash value of the variable data (i.e. excluding the
                 * name).
                 *
                 * Note: we already checked the general validity of the UEFI_VARIABLE_DATA structure, hence
                 * no need to do so again. */

                assert(record->firmware_payload_size >= offsetof(UEFI_VARIABLE_DATA, unicodeName));
                skip = offsetof(UEFI_VARIABLE_DATA, unicodeName) + vdata->unicodeNameLength * 2;

                assert(record->firmware_payload_size >= skip);
                hdata = (const uint8_t*) record->firmware_payload + skip;
                hsz = record->firmware_payload_size - skip;
                strict = true;
                break;
        }

        case EV_IPL:
                if (event_log_record_is_stub(record)) {
                        /* The PE section names have a descriptive string in UTF-16 in the payload, but the
                         * hash is over the UTF-8 version (with suffixing 0), hence let's convert the payload
                         * into that format here, and see if it checks out. */
                        hdata_alternative = utf16_to_utf8(record->firmware_payload, record->firmware_payload_size);
                        if (!hdata_alternative)
                                return log_oom();

                        hsz_alternative = strlen(hdata_alternative) + 1; /* with NUL byte */
                }

                _fallthrough_;

        default:
                /* For the others check the data too, just in case. But usually this will not match, hence
                 * only report if the checksum matches, but don't complain if it does not. */
                hdata = record->firmware_payload;
                hsz = record->firmware_payload_size;
                strict = false;
                break;
        }

        int mdsz = EVP_MD_size(md);
        assert(mdsz > 0);
        assert((size_t) mdsz <= sizeof_field(TPM2B_DIGEST, buffer));

        TPM2B_DIGEST payload_hash = {
                .size = mdsz,
        };

        unsigned dsz = mdsz;

        if (EVP_Digest(hdata, hsz, payload_hash.buffer, &dsz, md, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to calculate event payload hash.");
        assert(dsz == (unsigned) mdsz);

        /* If this didn't match then let's try the alternative format here, if we have one, and check things then. */
        if (memcmp_nn(bank->hash.buffer, bank->hash.size, payload_hash.buffer, payload_hash.size) != 0 && hdata_alternative) {
                if (EVP_Digest(hdata_alternative, hsz_alternative, payload_hash.buffer, &dsz, md, NULL) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to calculate event payload hash.");
                assert(dsz == (unsigned) mdsz);
        }

        if (memcmp_nn(bank->hash.buffer, bank->hash.size, payload_hash.buffer, payload_hash.size) != 0) {
                if (strict)
                        record->event_payload_valid = EVENT_PAYLOAD_VALID_NO;
                else if (record->event_payload_valid != EVENT_PAYLOAD_VALID_NO)
                        record->event_payload_valid = EVENT_PAYLOAD_VALID_DONT_KNOW;
        } else if (record->event_payload_valid < 0)
                record->event_payload_valid = EVENT_PAYLOAD_VALID_YES;

        return 1;
}

static int event_log_record_validate_hash_userspace(
                EventLogRecord *record,
                EventLogRecordBank *bank,
                const EVP_MD *md) {

        _cleanup_free_ unsigned char *payload_hash = NULL;
        unsigned payload_hash_size;
        JsonVariant *js;
        const char *s;
        int mdsz;

        assert(record);
        assert(bank);
        assert(md);

        if (!EVENT_LOG_RECORD_IS_USERSPACE(record))
                return 0;

        if (!record->userspace_content)
                return 0;

        js = json_variant_by_key(record->userspace_content, "string");
        if (!js)
                return 0;

        assert(json_variant_is_string(js));
        s = json_variant_string(js);

        mdsz = EVP_MD_size(md);
        assert(mdsz > 0);

        payload_hash_size = mdsz;
        payload_hash = malloc(payload_hash_size);
        if (!payload_hash)
                return log_oom();

        if (EVP_Digest(s, strlen(s), payload_hash, &payload_hash_size, md, NULL) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to calculate event payload hash.");

        assert((int) payload_hash_size == mdsz);
        if (memcmp_nn(bank->hash.buffer, bank->hash.size, payload_hash, payload_hash_size) != 0)
                record->event_payload_valid = EVENT_PAYLOAD_VALID_NO;
        else if (record->event_payload_valid < 0)
                record->event_payload_valid = EVENT_PAYLOAD_VALID_YES;

        return 0;
}

static int event_log_validate_record_hashes(EventLog *el) {
        int r;

        assert(el);

        /* For records which contain the full data to validate the hashes, do so. */

        FOREACH_ARRAY(rr, el->records, el->n_records) {

                LIST_FOREACH(banks, bank, (*rr)->banks) {
                        const EVP_MD *md;
                        const char *a;

                        assert_se(a = tpm2_hash_alg_to_string(bank->algorithm));
                        assert_se(md = EVP_get_digestbyname(a));

                        r = event_log_record_validate_hash_firmware(*rr, bank, md);
                        if (r < 0)
                                return r;

                        r = event_log_record_validate_hash_userspace(*rr, bank, md);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int event_log_component_cmp(EventLogComponent *const*a, EventLogComponent *const*b) {
        const EventLogComponent *x = ASSERT_PTR(*ASSERT_PTR(a)), *y = ASSERT_PTR(*ASSERT_PTR(b));

        return strcmp(x->id, y->id);
}

static EventLogComponent *event_log_find_component(EventLog *el, const char *id) {
        EventLogComponent k = {
                .id = (char*) id,
        };
        EventLogComponent *kk = &k, **found;

        assert(el);
        assert(id);

        found = typesafe_bsearch(
                        &kk,
                        el->components,
                        el->n_components,
                        event_log_component_cmp);
        if (!found)
                return NULL;

        return *found;
}

static int event_log_add_component(EventLog *el, const char *id, EventLogComponent **ret) {
        _cleanup_(event_log_component_freep) EventLogComponent *component = NULL;
        _cleanup_free_ char *id_copy = NULL;
        EventLogComponent *found;

        assert(el);
        assert(ret);

        found = event_log_find_component(el, id);
        if (found) {
                *ret = found;
                return 0;
        }

        if (!GREEDY_REALLOC(el->components, el->n_components+1))
                return log_oom();

        id_copy = strdup(id);
        if (!id_copy)
                return log_oom();

        component = new(EventLogComponent, 1);
        if (!component)
                return log_oom();

        *component = (EventLogComponent) {
                .id = TAKE_PTR(id_copy),
        };

        if (ret)
                *ret = component;

        el->components[el->n_components++] = TAKE_PTR(component);
        return 1;
}

static int event_log_record_equal(const EventLogRecord *a, const EventLogRecord *b) {
        EventLogRecordBank *x, *y;

        assert(a);
        assert(a->event_log);
        assert(b);
        assert(b->event_log);
        assert(a->event_log == b->event_log);

        if (a->pcr != b->pcr)
                return false;

        x = event_log_record_find_bank(a, a->event_log->primary_algorithm);
        y = event_log_record_find_bank(b, b->event_log->primary_algorithm);
        if (!x || !y)
                return false;

        assert(x->algorithm == a->event_log->primary_algorithm);
        assert(y->algorithm == b->event_log->primary_algorithm);

        return memcmp_nn(x->hash.buffer, x->hash.size, y->hash.buffer, y->hash.size) == 0;
}

static int event_log_add_component_file(EventLog *el, EventLogComponent *component, const char *path) {
        _cleanup_(event_log_component_variant_freep) EventLogComponentVariant *variant = NULL;
        _cleanup_free_ char *fname = NULL, *id = NULL, *path_copy = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *j = NULL;
        JsonVariant *records;
        const char *e;
        int r;

        assert(el);

        r = path_extract_filename(path, &fname);
        if (r < 0)
                return log_error_errno(r, "Failed to extract basename from path %s: %m", path);

        e = endswith(fname, ".pcrlock");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Bad suffix: %s", fname);

        id = strndup(fname, e - fname);
        if (!id)
                return log_oom();

        if (!component) {
                r = event_log_add_component(el, id, &component);
                if (r < 0)
                        return r;
        }

        if (!GREEDY_REALLOC(component->variants, component->n_variants+1))
                return log_oom();

        r = json_parse_file(
                        /* f= */ NULL,
                        path,
                        /* flags= */ 0,
                        &j,
                        /* ret_line= */ NULL,
                        /* ret_column= */ NULL);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse component file %s, ignoring: %m", path);
                return 0;
        }

        if (!json_variant_is_object(j)) {
                log_warning_errno(r, "Component file %s does not contain JSON object, ignoring.", path);
                return 0;
        }

        path_copy = strdup(path);
        if (!path_copy)
                return log_oom();

        variant = new(EventLogComponentVariant, 1);
        if (!variant)
                return log_oom();

        *variant = (EventLogComponentVariant) {
                .component = component,
                .path = TAKE_PTR(path_copy),
                .id = TAKE_PTR(id),
        };

        records = json_variant_by_key(j, "records");
        if (records) {
                JsonVariant *rj;

                if (!json_variant_is_array(records)) {
                        log_warning_errno(r, "Component records field of file %s is not an array, ignoring.", path);
                        return 0;
                }

                JSON_VARIANT_ARRAY_FOREACH(rj, records) {
                        _cleanup_(event_log_record_freep) EventLogRecord *record = NULL;

                        if (!GREEDY_REALLOC(variant->records, variant->n_records+1))
                                return log_oom();

                        record = event_log_record_new(el);
                        if (!record)
                                return log_oom();

                        r = event_log_record_parse_json(record, rj);
                        if (r < 0)
                                return r;

                        record->owning_component_variant = variant;
                        variant->records[variant->n_records++] = TAKE_PTR(record);
                }
        }

        component->variants[component->n_variants++] = TAKE_PTR(variant);
        return 1;
}

static int event_log_add_component_dir(EventLog *el, const char *path, char **base_search) {
        _cleanup_free_ char *fname = NULL, *id = NULL;
        _cleanup_strv_free_ char **files = NULL;
        EventLogComponent *component;
        const char *e;
        int r;

        assert(el);

        r = path_extract_filename(path, &fname);
        if (r < 0)
                return log_error_errno(r, "Failed to extract basename from path %s: %m", path);

        e = endswith(fname, ".pcrlock.d");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Bad suffix: %s", fname);

        id = strndup(fname, e - fname);
        if (!id)
                return log_oom();

        r = event_log_add_component(el, id, &component);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **search = NULL;

        STRV_FOREACH(b, base_search) {
                _cleanup_free_ char *q = NULL;

                q = path_join(*b, fname);
                if (!q)
                        return log_oom();

                r = strv_consume(&search, TAKE_PTR(q));
                if (r < 0)
                        return log_oom();
        }

        r = conf_files_list_strv(&files, ".pcrlock", /* root= */ NULL, CONF_FILES_REGULAR, (const char*const*) search);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate .pcrlock files for component '%s': %m", id);

        STRV_FOREACH(f, files) {
                r = event_log_add_component_file(el, component, *f);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int event_log_load_components(EventLog *el) {
        _cleanup_strv_free_ char **files = NULL;
        char **dirs;
        int r;

        assert(el);

        dirs = arg_components ?:
                STRV_MAKE("/etc/pcrlock.d",
                          "/run/pcrlock.d",
                          "/var/lib/pcrlock.d",
                          "/usr/local/lib/pcrlock.d",
                          "/usr/lib/pcrlock.d");

        r = conf_files_list_strv(&files, NULL, NULL, CONF_FILES_REGULAR|CONF_FILES_DIRECTORY|CONF_FILES_FILTER_MASKED, (const char*const*) dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate .pcrlock files: %m");

        STRV_FOREACH(f, files) {
                if (endswith(*f, ".pcrlock.d"))
                        r = event_log_add_component_dir(el, *f, dirs);
                else if (endswith(*f, ".pcrlock"))
                        r = event_log_add_component_file(el, NULL, *f);
                else
                        continue;
                if (r < 0)
                        return r;
        }

        return 0;
}

static int event_log_validate_fully_recognized(EventLog *el) {

        for (uint32_t pcr = 0; pcr < ELEMENTSOF(el->registers); pcr++) {
                bool fully_recognized = true;

                FOREACH_ARRAY(rr, el->records, el->n_records) {
                        EventLogRecord *rec = *rr;

                        if (rec->pcr != pcr)
                                continue;

                        if (rec->n_mapped == 0) {
                                log_notice("Event log record %zu (PCR %" PRIu32 ", \"%s\") not matching any component.",
                                           (size_t) (rr - el->records), rec->pcr, strna(rec->description));
                                fully_recognized = false;
                                break;
                        }
                }

                el->registers[pcr].fully_recognized = fully_recognized;
        }

        return 0;
}

static int event_log_match_component_variant(
                EventLog *el,
                size_t i,
                EventLogComponentVariant *variant,
                size_t j,
                bool assign) {

        int r;

        assert(el);
        assert(variant);

        /* It's OK to point immediately after the last record, but not further */
        assert(i <= el->n_records);
        assert(j <= variant->n_records);

        /* All entries in the variant checked out? Yippieh! */
        if (j == variant->n_records)
                return true;

        /* If the remainder of the variant is longer than the remainder of the event log, it cannot possibly fit. */
        if (el->n_records - i < variant->n_records - j)
                return false;

        /* Does this record match? If not, let's try at the next place in the logs. */
        if (!event_log_record_equal(el->records[i], variant->records[j]))
                return event_log_match_component_variant(el, i + 1, variant, j, assign); /* Recursion! */

        /* This one matches. Good. Let's see if the rest also matches. (Recursion!) */
        r = event_log_match_component_variant(el, i + 1, variant, j + 1, assign);
        if (r <= 0)
                return r;

        if (assign) {
                /* Take ownership (Note we allow multiple components and variants to take owneship of the same record!) */
                if (!GREEDY_REALLOC(el->records[i]->mapped, el->records[i]->n_mapped+1))
                        return log_oom();

                el->records[i]->mapped[el->records[i]->n_mapped++] = variant;
        }

        return true;
}

static uint32_t event_log_component_variant_pcrs(EventLogComponentVariant *i) {
        uint32_t mask = 0;

        assert(i);

        /* returns mask of PCRs touched by this variant */

        FOREACH_ARRAY(rr, i->records, i->n_records)
                mask |= UINT32_C(1) << (*rr)->pcr;

        return mask;
}

static uint32_t event_log_component_pcrs(EventLogComponent *c) {
        uint32_t mask = 0;

        assert(c);

        /* Returns mask of PCRs touched by this component */

        FOREACH_ARRAY(ii, c->variants, c->n_variants)
                mask |= event_log_component_variant_pcrs(*ii);

        return mask;
}

static int event_log_map_components(EventLog *el) {
        _cleanup_free_ char *skipped_ids = NULL;
        unsigned n_skipped = 0;
        int r;

        assert(el);

        FOREACH_ARRAY(cc, el->components, el->n_components) {
                _cleanup_free_ char *matching_ids = NULL;
                unsigned n_matching = 0, n_empty = 0;
                EventLogComponent *c = *cc;

                if (arg_location_end && strcmp(c->id, arg_location_end) > 0) {
                        n_skipped++;

                        if (!strextend_with_separator(&skipped_ids, ", ", c->id))
                                return log_oom();

                        continue;
                }

                FOREACH_ARRAY(ii, c->variants, c->n_variants) {
                        EventLogComponentVariant *i = *ii;

                        if (i->n_records == 0) {
                                /* The empty variant always matches */
                                n_empty++;
                                continue;
                        }

                        r = event_log_match_component_variant(el, 0, i, 0, n_matching + n_empty == 0);
                        if (r < 0)
                                return r;
                        if (r > 0) {
                                n_matching++;

                                if (!strextend_with_separator(&matching_ids, ", ", i->id))
                                        return log_oom();
                        }
                }

                if (n_matching + n_empty == 0) {

                        if (arg_location_start && strcmp(c->id, arg_location_start) >= 0)
                                log_info("Didn't find component '%s' in event log, assuming system hasn't reached it yet.", c->id);
                        else {
                                log_notice("Couldn't find component '%s' in event log.", c->id);
                                el->n_missing_components++;
                                el->missing_component_pcrs |= event_log_component_pcrs(c);
                        }
                } else if (n_matching > 1)
                        log_debug("Found %u possible variants of component '%s' in event log (%s). Proceeding.", n_matching, c->id, matching_ids);
        }

        if (n_skipped > 0)
                log_notice("Skipped %u components after location '%s' (%s).", n_skipped, arg_location_end, skipped_ids);
        if (el->n_missing_components > 0)
                log_notice("Unable to recognize %zu components in event log.", el->n_missing_components);

        return event_log_validate_fully_recognized(el);
}

#define ANSI_TRUE_COLOR_MAX (7U + 3U + 1U + 3U + 1U + 3U + 2U)

static const char *ansi_true_color(uint8_t r, uint8_t g, uint8_t b, char ret[static ANSI_TRUE_COLOR_MAX]) {
        snprintf(ret, ANSI_TRUE_COLOR_MAX, "\x1B[38;2;%u;%u;%um", r, g, b);
        return ret;
}

static char *color_for_pcr(EventLog *el, uint32_t pcr) {
        char color[ANSI_TRUE_COLOR_MAX];
        uint8_t r, g, b;

        assert(el);
        assert(pcr < TPM2_PCRS_MAX);

        if (el->registers[pcr].color)
                return el->registers[pcr].color;

        hsv_to_rgb(360.0 / (TPM2_PCRS_MAX - 1) * pcr, 100, 90, &r, &g, &b);
        ansi_true_color(r, g, b, color);

        el->registers[pcr].color = strdup(color);
        return el->registers[pcr].color;
}

static int add_algorithm_columns(
                EventLog *el,
                Table *table,
                const char *prefix,
                const char *json_field_prefix) {

        int r;

        assert(el);
        assert(table);

        FOREACH_ARRAY(alg, el->algorithms, el->n_algorithms) {
                const char *n = tpm2_hash_alg_to_string(*alg);
                _cleanup_free_ char *v = NULL;

                if (prefix)  {
                        v = strjoin(prefix, " ", n);
                        if (!v)
                                return log_oom();
                }

                size_t c = table_get_current_column(table);

                r = table_add_cell(table, NULL, TABLE_HEADER, v ?: n);
                if (r < 0)
                        return table_log_add_error(r);

                if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF) &&
                    el->primary_algorithm != UINT16_MAX &&
                    *alg != el->primary_algorithm)
                        (void) table_hide_column_from_display(table, c);

                _cleanup_free_ char *j = NULL;
                if (json_field_prefix) {
                        _cleanup_free_ char *m = strdup(n);
                        if (!m)
                                return log_oom();

                        j = strjoin(json_field_prefix, ascii_strupper(m));
                        if (!j)
                                return log_oom();
                }

                (void) table_set_json_field_name(table, c, j ?: n);
        }

        return 0;
}

static int show_log_table(EventLog *el, JsonVariant **ret_variant) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(el);

        table = table_new_raw(5 + el->n_algorithms + 4);
        if (!table)
                return log_oom();

        (void) table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        r = table_add_many(table,
                           TABLE_HEADER, "pcr",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_HEADER, "",
                           TABLE_HEADER, "pcrname",
                           TABLE_HEADER, "event",
                           TABLE_HEADER, "match",
                           TABLE_SET_ALIGN_PERCENT, 100);
        if (r < 0)
                return table_log_add_error(r);

        r = add_algorithm_columns(el, table, NULL, NULL);
        if (r < 0)
                return r;

        size_t phase_column = table_get_current_column(table);

        r = table_add_many(table,
                           TABLE_HEADER, "F/U",
                           TABLE_HEADER, "source",
                           TABLE_HEADER, "component",
                           TABLE_HEADER, "description");
        if (r < 0)
                return table_log_add_error(r);

        (void) table_hide_column_from_display(table, table_get_columns(table) - 3); /* hide source */

        if (!FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF))
                (void) table_hide_column_from_display(table, (size_t) 1); /* hide color block column */

        (void) table_set_json_field_name(table, phase_column, "phase");

        FOREACH_ARRAY(rr, el->records, el->n_records) {
                EventLogRecord *record = *rr;

                r = table_add_many(table,
                                   TABLE_UINT32, record->pcr,
                                   TABLE_STRING, special_glyph(SPECIAL_GLYPH_FULL_BLOCK),
                                   TABLE_SET_COLOR, color_for_pcr(el, record->pcr),
                                   TABLE_STRING, tpm2_pcr_index_to_string(record->pcr));
                if (r < 0)
                        return table_log_add_error(r);

                if (EVENT_LOG_RECORD_IS_FIRMWARE(record)) {
                        const char *et;

                        et = tpm2_log_event_type_to_string(record->firmware_event_type);
                        if (et)
                                r = table_add_cell(table, NULL, TABLE_STRING, et);
                        else
                                r = table_add_cell(table, NULL, TABLE_UINT32_HEX, &record->firmware_event_type);
                } else if (EVENT_LOG_RECORD_IS_USERSPACE(record))
                        r = table_add_cell(table, NULL, TABLE_STRING, tpm2_userspace_event_type_to_string(record->userspace_event_type));
                else
                        r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (record->event_payload_valid < 0 || record->event_payload_valid == EVENT_PAYLOAD_VALID_DONT_KNOW)
                        r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                else
                        r = table_add_many(table,
                                           TABLE_BOOLEAN_CHECKMARK, record->event_payload_valid == EVENT_PAYLOAD_VALID_YES,
                                           TABLE_SET_COLOR, ansi_highlight_green_red(record->event_payload_valid == EVENT_PAYLOAD_VALID_YES));
                if (r < 0)
                        return table_log_add_error(r);

                FOREACH_ARRAY(alg, el->algorithms, el->n_algorithms) {
                        EventLogRecordBank *bank;

                        bank = event_log_record_find_bank(record, *alg);
                        if (bank) {
                                _cleanup_free_ char *hex = NULL;

                                hex = hexmem(bank->hash.buffer, bank->hash.size);
                                if (!hex)
                                        return log_oom();

                                r = table_add_cell(table, NULL, TABLE_STRING, hex);
                        } else
                                r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_add_many(table,
                                   TABLE_STRING, EVENT_LOG_RECORD_IS_FIRMWARE(record) ? "F" :
                                                 EVENT_LOG_RECORD_IS_USERSPACE(record) ? "U" : NULL,
                                   TABLE_PATH_BASENAME, record->source,
                                   TABLE_PATH_BASENAME, record->n_mapped > 0 ? record->mapped[0]->component->id : NULL,
                                   TABLE_STRING, record->description);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (ret_variant) {
                r = table_to_json(table, ret_variant);
                if (r < 0)
                        return log_error_errno(r, "Failed to format table to JSON: %m");

                return 0;
        }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */true);
        if (r < 0)
                return log_error_errno(r, "Failed to output table: %m");

        return 0;
}

static bool is_unset_pcr(const void *value, size_t size) {
        return memeqzero(value, size) || memeqbyte(0xffu, value, size);
}

static bool event_log_pcr_checks_out(const EventLog *el, const EventLogRegister *reg) {
        assert(el);
        assert(reg);

        for (size_t i = 0; i < el->n_algorithms; i++)
                if (memcmp_nn(reg->banks[i].calculated.buffer, reg->banks[i].calculated.size,
                              reg->banks[i].observed.buffer, reg->banks[i].observed.size) != 0)
                        return false;

        return true;
}

static int show_pcr_table(EventLog *el, JsonVariant **ret_variant) {
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(el);

        table = table_new_raw(8 + el->n_algorithms*2);
        if (!table)
                return log_oom();

        (void) table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        r = table_add_many(table,
                           TABLE_HEADER, "pcr",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_HEADER, "", /* color block column */
                           TABLE_HEADER, "", /* emoji column */
                           TABLE_HEADER, "pcrname",
                           TABLE_HEADER, "count",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_HEADER, "h",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_HEADER, "r",
                           TABLE_SET_ALIGN_PERCENT, 100,
                           TABLE_HEADER, "c",
                           TABLE_SET_ALIGN_PERCENT, 100);
        if (r < 0)
                return table_log_add_error(r);

        r = add_algorithm_columns(el, table, "Calculated", "calculated");
        if (r < 0)
                return r;

        r = add_algorithm_columns(el, table, "Observed", "observed");
        if (r < 0)
                return r;

        if (!FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF))
                (void) table_hide_column_from_display(table, (size_t) 1, (size_t) 2); /* hide color block and emoji column */
        else if (!emoji_enabled())
                (void) table_hide_column_from_display(table, (size_t) 2);

        (void) table_set_json_field_name(table, 5, "hashMatchesEventLog");
        (void) table_set_json_field_name(table, 6, "allEventsMatched");
        (void) table_set_json_field_name(table, 7, "noMissingComponents");

        for (uint32_t pcr = 0; pcr < TPM2_PCRS_MAX; pcr++) {
                /* Check if the PCR hash value matches the event log data */
                bool hash_match = event_log_pcr_checks_out(el, el->registers + pcr);

                /* Whether all records in this PCR have a matching component */
                bool fully_recognized = el->registers[pcr].fully_recognized;

                /* Whether any unmatched components touch this PCR */
                bool missing_components = FLAGS_SET(el->missing_component_pcrs, UINT32_C(1) << pcr);

                const char *emoji = special_glyph(
                                !hash_match ? SPECIAL_GLYPH_DEPRESSED_SMILEY :
                                !fully_recognized ? SPECIAL_GLYPH_UNHAPPY_SMILEY :
                                missing_components ?  SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY :
                                SPECIAL_GLYPH_HAPPY_SMILEY);

                r = table_add_many(table,
                                   TABLE_UINT32, pcr,
                                   TABLE_STRING, special_glyph(SPECIAL_GLYPH_FULL_BLOCK),
                                   TABLE_SET_COLOR, color_for_pcr(el, pcr),
                                   TABLE_STRING, emoji,
                                   TABLE_STRING, tpm2_pcr_index_to_string(pcr));
                if (r < 0)
                        return table_log_add_error(r);

                if (el->registers[pcr].n_measurements > 0)
                        r = table_add_cell(table, NULL, TABLE_UINT, &el->registers[pcr].n_measurements);
                else
                        r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_many(table,
                                   TABLE_BOOLEAN_CHECKMARK, hash_match,
                                   TABLE_SET_COLOR, ansi_highlight_green_red(hash_match),
                                   TABLE_BOOLEAN_CHECKMARK, fully_recognized,
                                   TABLE_SET_COLOR, ansi_highlight_green_red(fully_recognized),
                                   TABLE_BOOLEAN_CHECKMARK, !missing_components,
                                   TABLE_SET_COLOR, ansi_highlight_green_red(!missing_components));
                if (r < 0)
                        return table_log_add_error(r);

                for (size_t i = 0; i < el->n_algorithms; i++) {
                        const char *color;

                        color = is_unset_pcr(el->registers[pcr].banks[i].calculated.buffer, el->registers[pcr].banks[i].calculated.size) ? ANSI_GREY : NULL;

                        if (el->registers[pcr].banks[i].calculated.size > 0) {
                                _cleanup_free_ char *hex = NULL;

                                hex = hexmem(el->registers[pcr].banks[i].calculated.buffer, el->registers[pcr].banks[i].calculated.size);
                                if (!hex)
                                        return log_oom();

                                r = table_add_many(table,
                                                   TABLE_STRING, hex,
                                                   TABLE_SET_COLOR, color);
                        } else
                                r = table_add_many(table,
                                                   TABLE_EMPTY,
                                                   TABLE_SET_COLOR, color);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                for (size_t i = 0; i < el->n_algorithms; i++) {
                        _cleanup_free_ char *hex = NULL;
                        const char *color;

                        hex = hexmem(el->registers[pcr].banks[i].observed.buffer, el->registers[pcr].banks[i].observed.size);
                        if (!hex)
                                return log_oom();

                        color = !hash_match ? ANSI_HIGHLIGHT_RED :
                                is_unset_pcr(el->registers[pcr].banks[i].observed.buffer, el->registers[pcr].banks[i].observed.size) ? ANSI_GREY : NULL;

                        r = table_add_many(table,
                                           TABLE_STRING, hex,
                                           TABLE_SET_COLOR, color);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        if (ret_variant) {
                r = table_to_json(table, ret_variant);
                if (r < 0)
                        return log_error_errno(r, "Failed to format table to JSON: %m");

                return 0;
        }

        r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */ true);
        if (r < 0)
                return log_error_errno(r, "Failed to output table: %m");

        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF))
                printf("\n"
                       "%sLegend: H → PCR hash value matches event log%s\n"
                       "%s        R → All event log records for this PCR have a matching component%s\n"
                       "%s        C → No components that couldn't be matched with log records affect this PCR%s\n",
                       ansi_grey(), ansi_normal(), /* less on small screens automatically resets the color after long lines, hence we set it anew for each line */
                       ansi_grey(), ansi_normal(),
                       ansi_grey(), ansi_normal());

        return 0;
}

static int event_determine_primary_algorithm(EventLog *el) {
        assert(el);

        if (el->n_algorithms == 0) {
                /* Nothing loaded to make the decision on? Then pick SHA256 */
                el->primary_algorithm = TPM2_ALG_SHA256;
                return 0;
        }

        FOREACH_ARRAY(alg, el->algorithms, el->n_algorithms) {
                /* If we have SHA256, focus on that that */

                if (*alg == TPM2_ALG_SHA256) {
                        el->primary_algorithm = *alg;
                        return 0;
                }
        }

        /* Otherwise show the "best" (i.e. the one with the highest id value) */
        el->primary_algorithm = el->algorithms[el->n_algorithms-1];
        return 0;
}

static int event_log_load_and_process(EventLog **ret) {
        _cleanup_(event_log_freep) EventLog *el = NULL;
        int r;

        el = event_log_new();
        if (!el)
                return log_oom();

        r = event_log_add_algorithms_from_environment(el);
        if (r < 0)
                return r;

        r = event_log_load(el);
        if (r < 0)
                return r;

        r = event_log_read_pcrs(el);
        if (r < 0)
                return r;

        r = event_log_calculate_pcrs(el);
        if (r < 0)
                return r;

        r = event_log_validate_record_hashes(el);
        if (r < 0)
                return r;

        r = event_determine_primary_algorithm(el);
        if (r < 0)
                return r;

        r = event_log_load_components(el);
        if (r < 0)
                return r;

        r = event_log_map_components(el);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(el);
        return 0;
}

static int verb_show_log(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *log_table = NULL, *pcr_table = NULL;
        _cleanup_(event_log_freep) EventLog *el = NULL;
        bool want_json = !FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF);
        int r;

        r = event_log_load_and_process(&el);
        if (r < 0)
                return r;

        if (!want_json)
                putchar('\n');

        r = show_log_table(el, want_json ? &log_table : NULL);
        if (r < 0)
                return r;

        if (!want_json)
                putchar('\n');

        r = show_pcr_table(el, want_json ? &pcr_table : NULL);
        if (r < 0)
                return r;

        if (want_json) {
                _cleanup_(json_variant_unrefp) JsonVariant *object = NULL;

                r = json_build(&object, JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR_VARIANT("log", log_table),
                                               JSON_BUILD_PAIR_VARIANT("pcrs", pcr_table)));
                if (r < 0)
                        return log_error_errno(r, "Failed to generate combined object: %m");

                r = json_variant_dump(object, arg_json_format_flags, stdout, /* prefix= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to dump JSON object: %m");
        }

        return 0;
}

static int verb_show_cel(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        _cleanup_(event_log_freep) EventLog *el = NULL;
        uint64_t recnum = 0;
        int r;

        el = event_log_new();
        if (!el)
                return log_oom();

        r = event_log_load(el);
        if (r < 0)
                return r;

        /* Output the event log in TCG CEL-JSON. */

        FOREACH_ARRAY(rr, el->records, el->n_records) {
                _cleanup_(json_variant_unrefp) JsonVariant *ja = NULL, *fj = NULL;
                EventLogRecord *record = *rr;
                JsonVariant *cd = NULL;
                const char *ct = NULL;

                LIST_FOREACH(banks, bank, record->banks) {
                        r = json_variant_append_arrayb(
                                        &ja, JSON_BUILD_OBJECT(
                                                        JSON_BUILD_PAIR_STRING("hashAlg", tpm2_hash_alg_to_string(bank->algorithm)),
                                                        JSON_BUILD_PAIR_HEX("digest", bank->hash.buffer, bank->hash.size)));
                        if (r < 0)
                                return log_error_errno(r, "Failed to append CEL digest entry: %m");
                }

                if (!ja) {
                        r = json_variant_new_array(&ja, NULL, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate JSON array: %m");
                }

                if (EVENT_LOG_RECORD_IS_FIRMWARE(record)) {
                        _cleanup_free_ char *et = NULL;
                        const char *z;

                        z = tpm2_log_event_type_to_string(record->firmware_event_type);
                        if (z) {
                                _cleanup_free_ char *b = NULL;

                                b = strreplace(z, "-", "_");
                                if (!b)
                                        return log_oom();

                                et = strjoin("EV_", ascii_strupper(b));
                                if (!et)
                                        return log_oom();
                        } else if (asprintf(&et, "%" PRIu32, record->firmware_event_type) < 0)
                                return log_oom();

                        r = json_build(&fj, JSON_BUILD_OBJECT(
                                                       JSON_BUILD_PAIR_STRING("event_type", et),
                                                       JSON_BUILD_PAIR_HEX("event_data", record->firmware_payload, record->firmware_payload_size)));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build firmware event data: %m");

                        cd = fj;
                        ct = "pcclient_std";
                } else if (EVENT_LOG_RECORD_IS_USERSPACE(record)) {
                        cd = record->userspace_content;
                        ct = "systemd";
                }

                r = json_variant_append_arrayb(&array,
                                         JSON_BUILD_OBJECT(
                                                         JSON_BUILD_PAIR_UNSIGNED("pcr", record->pcr),
                                                         JSON_BUILD_PAIR_UNSIGNED("recnum", ++recnum),
                                                         JSON_BUILD_PAIR_VARIANT("digests", ja),
                                                         JSON_BUILD_PAIR_CONDITION(ct, "content_type", JSON_BUILD_STRING(ct)),
                                                         JSON_BUILD_PAIR_CONDITION(cd, "content", JSON_BUILD_VARIANT(cd))));
                if (r < 0)
                        return log_error_errno(r, "Failed to append CEL record: %m");
        }

        if (arg_json_format_flags & (JSON_FORMAT_PRETTY|JSON_FORMAT_PRETTY_AUTO))
                pager_open(arg_pager_flags);

        json_variant_dump(array, arg_json_format_flags|JSON_FORMAT_EMPTY_ARRAY, stdout, NULL);
        return 0;
}

static int verb_list_components(int argc, char *argv[], void *userdata) {
        _cleanup_(event_log_freep) EventLog *el = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        enum {
                BEFORE_LOCATION,
                BETWEEN_LOCATION,
                AFTER_LOCATION,
        } loc = BEFORE_LOCATION;
        int r;

        el = event_log_new();
        if (!el)
                return log_oom();

        r = event_log_add_algorithms_from_environment(el);
        if (r < 0)
                return r;

        r = event_determine_primary_algorithm(el);
        if (r < 0)
                return r;

        r = event_log_load_components(el);
        if (r < 0)
                return r;

        table = table_new("id", "variants");
        if (!table)
                return log_oom();

        FOREACH_ARRAY(c, el->components, el->n_components) {

                if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF)) {
                        _cleanup_free_ char *marker = NULL;

                        switch (loc) {

                        case BEFORE_LOCATION:
                                if (arg_location_end && strcmp((*c)->id, arg_location_end) >= 0) {
                                        loc = AFTER_LOCATION;
                                        marker = strjoin(special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), " location '", arg_location_end, "' ", special_glyph(SPECIAL_GLYPH_ARROW_LEFT));
                                } else if (arg_location_start && strcmp((*c)->id, arg_location_start) >= 0) {
                                        loc = BETWEEN_LOCATION;
                                        marker = strjoin(special_glyph(SPECIAL_GLYPH_TREE_TOP), " start location '", arg_location_start, "' ", special_glyph(SPECIAL_GLYPH_ARROW_DOWN));
                                }

                                break;

                        case BETWEEN_LOCATION:
                                if (arg_location_end && strcmp((*c)->id, arg_location_end) >= 0) {
                                        loc = AFTER_LOCATION;
                                        marker = strjoin(special_glyph(SPECIAL_GLYPH_TREE_RIGHT), " end location '", arg_location_end, "' ", special_glyph(SPECIAL_GLYPH_ARROW_UP));
                                }
                                break;

                        case AFTER_LOCATION:
                                break;
                        }

                        if (marker) {
                                r = table_add_many(table,
                                                   TABLE_STRING, marker,
                                                   TABLE_SET_COLOR, ANSI_GREY,
                                                   TABLE_EMPTY);
                                if (r < 0)
                                        return table_log_add_error(r);
                        }
                }

                FOREACH_ARRAY(variant, (*c)->variants, (*c)->n_variants) {
                        r = table_add_many(table,
                                           TABLE_STRING, (*c)->id,
                                           TABLE_PATH, (*variant)->path);
                        if (r < 0)
                                return table_log_add_error(r);
                }
        }

        if (!table_isempty(table) || !FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF)) {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */ true);
                if (r < 0)
                        return log_error_errno(r, "Failed to output table: %m");
        }

        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF)) {
                if (table_isempty(table))
                        printf("No components defined.\n");
                else
                        printf("\n%zu components listed.\n", table_get_rows(table) - 1);
        }

        return 0;
}

static int event_log_pcr_mask_checks_out(EventLog *el, uint32_t mask) {
        assert(el);

        for (uint32_t pcr = 0; pcr < TPM2_PCRS_MAX; pcr++) {

                if (!FLAGS_SET(mask, UINT32_C(1) << pcr))
                        continue;

                if (!event_log_pcr_checks_out(el, el->registers + pcr))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Event log for PCR %" PRIu32 " does not match PCR state, refusing.", pcr);
        }

        return 0;
}

static int make_pcrlock_record(
                uint32_t pcr,
                const void *data,
                size_t data_size,
                JsonVariant **ret_record) {

        _cleanup_(json_variant_unrefp) JsonVariant *digests = NULL;
        int r;

        assert(data || data_size == 0);
        assert(ret_record);

        if (data_size == SIZE_MAX)
                data_size = strlen(data);

        /* Generates a .pcrlock record for the given PCR and data/data size. This is a subset of TCG CEL. */

        FOREACH_ARRAY(pa, tpm2_hash_algorithms, TPM2_N_HASH_ALGORITHMS) {
                _cleanup_free_ unsigned char *hash = NULL;
                int hash_ssize;
                unsigned hash_usize;
                const EVP_MD *md;
                const char *a;

                assert_se(a = tpm2_hash_alg_to_string(*pa));
                assert_se(md = EVP_get_digestbyname(a));
                hash_ssize = EVP_MD_size(md);
                assert_se(hash_ssize > 0);
                hash_usize = hash_ssize;

                hash = malloc(hash_usize);
                if (!hash)
                        return log_oom();

                if (EVP_Digest(data, data_size, hash, &hash_usize, md, NULL) != 1)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to hash data with algorithm '%s'.", a);

                r = json_variant_append_arrayb(
                                &digests,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR("hashAlg", JSON_BUILD_STRING(a)),
                                                JSON_BUILD_PAIR("digest", JSON_BUILD_HEX(hash, hash_usize))));
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON digest object: %m");
        }

        r = json_build(ret_record,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("pcr", JSON_BUILD_UNSIGNED(pcr)),
                                       JSON_BUILD_PAIR("digests", JSON_BUILD_VARIANT(digests))));
        if (r < 0)
                return log_error_errno(r, "Failed to build record object: %m");

        return 0;
}

static const char *pcrlock_path(const char *default_pcrlock_path) {
        return arg_pcrlock_path ?: arg_pcrlock_auto ? default_pcrlock_path : NULL;
}

static int write_pcrlock(JsonVariant *array, const char *default_pcrlock_path) {
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL, *a = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        const char *p;
        int r;

        if (!array) {
                r = json_variant_new_array(&a, NULL, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate empty array: %m");

                array = a;
        }

        r = json_build(&v, JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR("records", JSON_BUILD_VARIANT(array))));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        p = pcrlock_path(default_pcrlock_path);
        if (p) {
                (void) mkdir_parents_label(p, 0755);

                f = fopen(p, "we");
                if (!f)
                        return log_error_errno(errno, "Failed to open %s for writing: %m", p);
        }

        r = json_variant_dump(v, arg_json_format_flags, f ?: stdout, /* prefix= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to output JSON object: %m");

        if (p)
                log_info("%s written.", p);

        return 0;
}

static int unlink_pcrlock(const char *default_pcrlock_path) {
        const char *p;

        p = pcrlock_path(default_pcrlock_path);
        if (!p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No .pcrlock path specified, refusing.");

        if (unlink(p) < 0) {
                if (errno != ENOENT)
                        return log_error_errno(errno, "Failed to delete %s: %m", p);

                log_info("%s already deleted.", p);
        } else
                log_info("%s deleted.", p);

        (void) rmdir_parents(p, "/var/lib");

        return 0;
}

static int verb_lock_raw(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        _cleanup_free_ char *data = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t size;
        int r;

        if (arg_pcr_mask == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No PCR specified, refusing.");

        if (argc >= 2) {
                f = fopen(argv[1], "re");
                if (!f)
                        return log_error_errno(errno, "Failed to open '%s': %m", argv[1]);
        }

        r = read_full_stream(f ?: stdin, &data, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read data from stdin: %m");

        for (uint32_t i = 0; i < TPM2_PCRS_MAX; i++) {
                _cleanup_(json_variant_unrefp) JsonVariant *record = NULL;

                if (!FLAGS_SET(arg_pcr_mask, UINT32_C(1) << i))
                        continue;

                r = make_pcrlock_record(i, data, size, &record);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&array, record);
                if (r < 0)
                        return log_error_errno(r, "Failed to append to JSON array: %m");
        }

        return write_pcrlock(array, NULL);
}

static int verb_unlock_simple(int argc, char *argv[], void *userdata) {
        return unlink_pcrlock(NULL);
}

static int verb_lock_secureboot_policy(int argc, char *argv[], void *userdata) {
        static const struct {
                sd_id128_t id;
                const char *name;
                int synthesize_empty; /* 0 → fail, > 0 → synthesize empty db, < 0 → skip */
        } variables[] = {
                { EFI_VENDOR_GLOBAL,   "SecureBoot", 0 },
                { EFI_VENDOR_GLOBAL,   "PK",         0 },
                { EFI_VENDOR_GLOBAL,   "KEK",        0 },
                { EFI_VENDOR_DATABASE, "db",         1 },
                { EFI_VENDOR_DATABASE, "dbx",        1 },
                { EFI_VENDOR_DATABASE, "dbt",       -1 },
                { EFI_VENDOR_DATABASE, "dbr",       -1 },
        };

        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        int r;

        /* Generates expected records from the current SecureBoot state, as readable in the EFI variables
         * right now. */

        FOREACH_ARRAY(vv, variables, ELEMENTSOF(variables)) {
                _cleanup_(json_variant_unrefp) JsonVariant *record = NULL;

                _cleanup_free_ char *name = NULL;
                if (asprintf(&name, "%s-" SD_ID128_UUID_FORMAT_STR, vv->name, SD_ID128_FORMAT_VAL(vv->id)) < 0)
                        return log_oom();

                _cleanup_free_ void *data = NULL;
                size_t data_size;
                r = efi_get_variable(name, NULL, &data, &data_size);
                if (r < 0) {
                        if (r != -ENOENT || vv->synthesize_empty == 0)
                                return log_error_errno(r, "Failed to read EFI variable '%s': %m", name);
                        if (vv->synthesize_empty < 0)
                                continue;

                        /* If the main database variables are not set we don't consider this an error, but
                         * measure an empty database instead. */
                        log_debug("EFI variable %s is not set, synthesizing empty variable for measurement.", name);
                        data_size = 0;
                }

                _cleanup_free_ char16_t* name16 = utf8_to_utf16(vv->name, SIZE_MAX);
                if (!name16)
                        return log_oom();
                size_t name16_bytes = char16_strlen(name16) * 2;

                size_t vdata_size = offsetof(UEFI_VARIABLE_DATA, unicodeName) + name16_bytes + data_size;
                _cleanup_free_ UEFI_VARIABLE_DATA *vdata = malloc(vdata_size);
                if (!vdata)
                        return log_oom();

                *vdata = (UEFI_VARIABLE_DATA) {
                        .unicodeNameLength = name16_bytes / 2,
                        .variableDataLength = data_size,
                };

                efi_id128_to_guid(vv->id, vdata->variableName);
                memcpy(mempcpy(vdata->unicodeName, name16, name16_bytes), data, data_size);

                r = make_pcrlock_record(TPM2_PCR_SECURE_BOOT_POLICY /* =7 */, vdata, vdata_size, &record);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&array, record);
                if (r < 0)
                        return log_error_errno(r, "Failed to append to JSON array: %m");
        }

        return write_pcrlock(array, PCRLOCK_SECUREBOOT_POLICY_PATH);
}

static int verb_unlock_secureboot_policy(int argc, char *argv[], void *userdata) {
        return unlink_pcrlock(PCRLOCK_SECUREBOOT_POLICY_PATH);
}

static int event_log_record_is_secureboot_variable(EventLogRecord *rec, sd_id128_t uuid, const char *name) {
        _cleanup_free_ char *found_name = NULL;
        sd_id128_t found_uuid;
        int r;

        assert(rec);
        assert(name);

        if (!EVENT_LOG_RECORD_IS_FIRMWARE(rec))
                return false;

        if (rec->pcr != TPM2_PCR_SECURE_BOOT_POLICY)
                return false;

        if (rec->event_payload_valid != EVENT_PAYLOAD_VALID_YES)
                return false;

        if (rec->firmware_event_type != EV_EFI_VARIABLE_DRIVER_CONFIG)
                return false;

        r = event_log_record_parse_variable_data(rec, &found_uuid, &found_name);
        if (r == -EBADMSG)
                return false;
        if (r < 0)
                return r;

        if (!sd_id128_equal(found_uuid, uuid))
                return false;

        return streq(found_name, name);
}

static bool event_log_record_is_secureboot_authority(EventLogRecord *rec) {
        assert(rec);

        if (!EVENT_LOG_RECORD_IS_FIRMWARE(rec))
                return false;

        if (rec->pcr != TPM2_PCR_SECURE_BOOT_POLICY)
                return false;

        if (rec->event_payload_valid != EVENT_PAYLOAD_VALID_YES)
                return false;

        return rec->firmware_event_type == EV_EFI_VARIABLE_AUTHORITY;
}

static int event_log_ensure_secureboot_consistency(EventLog *el) {
        static const struct {
                sd_id128_t id;
                const char *name;
                bool required;
        } table[] = {
                { EFI_VENDOR_GLOBAL,   "SecureBoot", true  },
                { EFI_VENDOR_GLOBAL,   "PK",         true  },
                { EFI_VENDOR_GLOBAL,   "KEK",        true  },
                { EFI_VENDOR_DATABASE, "db",         true  },
                { EFI_VENDOR_DATABASE, "dbx",        true  },
                { EFI_VENDOR_DATABASE, "dbt",        false },
                { EFI_VENDOR_DATABASE, "dbr",        false },
                // FIXME: ensure we also find the separator here
        };

        EventLogRecord *records[ELEMENTSOF(table)] = {};
        EventLogRecord *first_authority = NULL;

        assert(el);

        /* Ensures that the PCR 7 records are complete and in order. Before we lock down PCR 7 we want to
         * ensure its state is actually consistent. */

        FOREACH_ARRAY(rr, el->records, el->n_records) {
                EventLogRecord *rec = *rr;
                size_t found = SIZE_MAX;

                if (event_log_record_is_secureboot_authority(rec)) {
                        if (first_authority)
                                continue;

                        first_authority = rec;
                        // FIXME: also check that each authority record's data is also listed in 'db'
                        continue;
                }

                for (size_t i = 0; i < ELEMENTSOF(table); i++)
                        if (event_log_record_is_secureboot_variable(rec, table[i].id, table[i].name)) {
                                found = i;
                                break;
                        }
                if (found == SIZE_MAX)
                        continue;

                /* Require the authority records always come *after* database measurements */
                if (first_authority)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "SecureBoot authority before variable, refusing.");

                /* Check for duplicates */
                if (records[found])
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Duplicate '%s' record, refusing.", rec->description);

                /* Check for order */
                for (size_t j = found + 1; j < ELEMENTSOF(table); j++)
                        if (records[j])
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'%s' record before '%s' record, refusing.", records[j]->description, rec->description);

                records[found] = rec;
        }

        /* Check for existence */
        for (size_t i = 0; i < ELEMENTSOF(table); i++)
                if (table[i].required && !records[i])
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Required record '%s' not found, refusing.", table[i].name);

        /* At this point we know that all required variables have been measured, in the right order. */
        return 0;
}

static int verb_lock_secureboot_authority(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        _cleanup_(event_log_freep) EventLog *el = NULL;
        int r;

        /* Lock down the EV_EFI_VARIABLE_AUTHORITY records from the existing log. Note that there's not too
         * much value in locking this down too much, since it stores only the result of the primary database
         * checks, and that's what we should bind policy to. Moreover it's hard to predict, since extension
         * card firmware validation will result in additional records here. */

        if (!is_efi_secure_boot()) {
                log_info("SecureBoot disabled, not generating authority .pcrlock file.");
                return unlink_pcrlock(PCRLOCK_SECUREBOOT_AUTHORITY_PATH);
        }

        el = event_log_new();
        if (!el)
                return log_oom();

        r = event_log_add_algorithms_from_environment(el);
        if (r < 0)
                return r;

        r = event_log_load(el);
        if (r < 0)
                return r;

        r = event_log_read_pcrs(el);
        if (r < 0)
                return r;

        r = event_log_calculate_pcrs(el);
        if (r < 0)
                return r;

        /* Before we base anything on the event log records, let's check that the event log state checks
         * out. */

        r = event_log_pcr_mask_checks_out(el, UINT32_C(1) << TPM2_PCR_SECURE_BOOT_POLICY);
        if (r < 0)
                return r;

        r = event_log_validate_record_hashes(el);
        if (r < 0)
                return r;

        r = event_log_ensure_secureboot_consistency(el);
        if (r < 0)
                return r;

        FOREACH_ARRAY(rr, el->records, el->n_records) {
                _cleanup_(json_variant_unrefp) JsonVariant *digests = NULL;
                EventLogRecord *rec = *rr;

                if (!event_log_record_is_secureboot_authority(rec))
                        continue;

                log_debug("Locking down authority '%s'.", strna(rec->description));

                LIST_FOREACH(banks, bank, rec->banks) {
                        r = json_variant_append_arrayb(
                                        &digests,
                                        JSON_BUILD_OBJECT(
                                                        JSON_BUILD_PAIR("hashAlg", JSON_BUILD_STRING(tpm2_hash_alg_to_string(bank->algorithm))),
                                                        JSON_BUILD_PAIR("digest", JSON_BUILD_HEX(bank->hash.buffer, bank->hash.size))));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build digests array: %m");
                }

                r = json_variant_append_arrayb(
                                &array,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR("pcr", JSON_BUILD_UNSIGNED(rec->pcr)),
                                                JSON_BUILD_PAIR("digests", JSON_BUILD_VARIANT(digests))));
                if (r < 0)
                        return log_error_errno(r, "Failed to build record array: %m");
        }

        return write_pcrlock(array, PCRLOCK_SECUREBOOT_AUTHORITY_PATH);
}

static int verb_unlock_secureboot_authority(int argc, char *argv[], void *userdata) {
        return unlink_pcrlock(PCRLOCK_SECUREBOOT_AUTHORITY_PATH);
}

static int verb_lock_gpt(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL, *record = NULL;
        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        uint8_t h[2 * 4096]; /* space for at least two 4K sectors. GPT header should definitely be in here */
        uint64_t start, n_members, member_size;
        _cleanup_close_ int fd = -EBADF;
        const GptHeader *p;
        size_t found = 0;
        ssize_t n;
        int r;

        r = block_device_new_from_path(
                        argc >= 2 ? argv[1] : "/",
                        BLOCK_DEVICE_LOOKUP_WHOLE_DISK|BLOCK_DEVICE_LOOKUP_BACKING|BLOCK_DEVICE_LOOKUP_ORIGINATING,
                        &d);
        if (r < 0)
                return log_error_errno(r, "Failed to determine root block device: %m");

        fd = sd_device_open(d, O_CLOEXEC|O_RDONLY|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open root block device: %m");

        n = pread(fd, &h, sizeof(h), 0);
        if (n < 0)
                return log_error_errno(errno, "Failed to read GPT header of block device: %m");
        if ((size_t) n != sizeof(h))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read trying to read GPT header: %m");

        /* Try a couple of sector sizes */
        for (size_t sz = 512; sz <= 4096; sz <<= 1) {
                assert(sizeof(h) >= sz * 2);
                p = (const GptHeader*) (h + sz); /* 2nd sector */

                if (!gpt_header_has_signature(p))
                        continue;

                if (found != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                               "Disk has partition table for multiple sector sizes, refusing.");

                found = sz;
        }

        if (found == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Disk does not have GPT partition table, refusing.");

        p = (const GptHeader*) (h + found);

        if (le32toh(p->header_size) > found)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "GPT header size over long (%" PRIu32 "), refusing.", le32toh(p->header_size));

        start = le64toh(p->partition_entry_lba);
        if (start > UINT64_MAX / found)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Partition table start offset overflow, refusing.");

        member_size = le32toh(p->size_of_partition_entry);
        if (member_size < sizeof(GptPartitionEntry))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Partition entry size too short, refusing.");

        n_members = le32toh(p->number_of_partition_entries);
        uint64_t member_bufsz = n_members * member_size;
        if (member_bufsz > 1U*1024U*1024U)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Partition table size too large, refusing.");

        member_bufsz = ROUND_UP(member_bufsz, found);

        _cleanup_free_ void *members = malloc(member_bufsz);
        if (!members)
                return log_oom();

        n = pread(fd, members, member_bufsz, start * found);
        if (n < 0)
                return log_error_errno(errno, "Failed to read GPT partition table entries: %m");
        if ((size_t) n != member_bufsz)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading GPT partition table entries: %m");

        size_t vdata_size = le32toh(p->header_size) + sizeof(le64_t) + member_size * n_members;
        _cleanup_free_ void *vdata = malloc0(vdata_size);
        if (!vdata)
                return log_oom();

        void *n_measured_entries = mempcpy(vdata, p, sizeof(GptHeader)); /* n_measured_entries is a 64bit value */

        void *qq = (uint8_t*) n_measured_entries + sizeof(le64_t);

        for (uint64_t i = 0; i < n_members; i++) {
                const GptPartitionEntry *entry = (const GptPartitionEntry*) ((const uint8_t*) members + (member_size * i));

                if (memeqzero(entry->partition_type_guid, sizeof(entry->partition_type_guid)))
                        continue;

                qq = mempcpy(qq, entry, member_size);
                unaligned_write_le64(n_measured_entries, unaligned_read_le64(n_measured_entries) + 1);
        }

        vdata_size = (uint8_t*) qq - (uint8_t*) vdata;

        r = make_pcrlock_record(TPM2_PCR_BOOT_LOADER_CONFIG /* =5 */, vdata, vdata_size, &record);
        if (r < 0)
                return r;

        r = json_variant_new_array(&array, &record, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to append to JSON array: %m");

        return write_pcrlock(array, PCRLOCK_GPT_PATH);
}

static int verb_unlock_gpt(int argc, char *argv[], void *userdata) {
        return unlink_pcrlock(PCRLOCK_GPT_PATH);
}

static bool event_log_record_is_separator(const EventLogRecord *rec) {
        assert(rec);

        /* Recognizes EV_SEPARATOR events */

        if (!EVENT_LOG_RECORD_IS_FIRMWARE(rec))
                return false;

        if (rec->firmware_event_type != EV_SEPARATOR)
                return false;

        return rec->event_payload_valid == EVENT_PAYLOAD_VALID_YES; /* Insist the record is consistent */
}

static int event_log_record_is_action_calling_efi_app(const EventLogRecord *rec) {
        _cleanup_free_ char *d = NULL;
        int r;

        assert(rec);

        /* Recognizes the special EV_EFI_ACTION that is issues when the firmware passes control to the boot loader. */

        if (!EVENT_LOG_RECORD_IS_FIRMWARE(rec))
                return false;

        if (rec->pcr != TPM2_PCR_BOOT_LOADER_CODE)
                return false;

        if (rec->firmware_event_type != EV_EFI_ACTION)
                return false;

        if (rec->event_payload_valid != EVENT_PAYLOAD_VALID_YES) /* Insist the record is consistent */
                return false;

        r = make_cstring(rec->firmware_payload, rec->firmware_payload_size, MAKE_CSTRING_ALLOW_TRAILING_NUL, &d);
        if (r < 0)
                return r;

        return streq(d, "Calling EFI Application from Boot Option");
}

static void enable_json_sse(void) {
        /* We shall write this to a single output stream? We have to output two files, hence try to be smart
         * and enable JSON SSE */

        if (!arg_pcrlock_path && arg_pcrlock_auto)
                return;

        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_SSE))
                return;

        log_notice("Enabling JSON_SEQ mode, since writing two .pcrlock files to single output.");
        arg_json_format_flags |= JSON_FORMAT_SSE;
}

static int verb_lock_firmware(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *array_early = NULL, *array_late = NULL;
        _cleanup_(event_log_freep) EventLog *el = NULL;
        uint32_t always_mask, separator_mask, separator_seen_mask = 0, action_seen_mask = 0;
        const char *default_pcrlock_early_path, *default_pcrlock_late_path;
        int r;

        enable_json_sse();

        /* The PCRs we intend to cover. Note that we measure firmware, external *and* boot loader code/config
         * here – but the latter only until the "separator" events are seen, which tell us where transition
         * into OS boot loader happens. This reflects the fact that on some systems the firmware already
         * measures some firmware-supplied apps into PCR 4. (e.g. Thinkpad X1 Gen9) */
        if (endswith(argv[0], "firmware-code")) {
                always_mask = (UINT32_C(1) << TPM2_PCR_PLATFORM_CODE) |      /* → 0 */
                        (UINT32_C(1) << TPM2_PCR_EXTERNAL_CODE);             /* → 2 */

                separator_mask = UINT32_C(1) << TPM2_PCR_BOOT_LOADER_CODE;   /* → 4 */

                default_pcrlock_early_path = PCRLOCK_FIRMWARE_CODE_EARLY_PATH;
                default_pcrlock_late_path = PCRLOCK_FIRMWARE_CODE_LATE_PATH;
        } else {
                assert(endswith(argv[0], "firmware-config"));
                always_mask = (UINT32_C(1) << TPM2_PCR_PLATFORM_CONFIG) |    /* → 1 */
                        (UINT32_C(1) << TPM2_PCR_EXTERNAL_CONFIG);           /* → 3 */

                separator_mask = UINT32_C(1) << TPM2_PCR_BOOT_LOADER_CONFIG; /* → 5 */

                default_pcrlock_early_path = PCRLOCK_FIRMWARE_CONFIG_EARLY_PATH;
                default_pcrlock_late_path = PCRLOCK_FIRMWARE_CONFIG_LATE_PATH;
        }

        el = event_log_new();
        if (!el)
                return log_oom();

        r = event_log_add_algorithms_from_environment(el);
        if (r < 0)
                return r;

        r = event_log_load(el);
        if (r < 0)
                return r;

        r = event_log_read_pcrs(el);
        if (r < 0)
                return r;

        r = event_log_calculate_pcrs(el);
        if (r < 0)
                return r;

        r = event_log_validate_record_hashes(el);
        if (r < 0)
                return r;

        /* Before we base anything on the event log records for any of the selected PCRs, let's check that
         * the event log state checks out for them. */

        r = event_log_pcr_mask_checks_out(el, always_mask|separator_mask);
        if (r < 0)
                return r;

        // FIXME: before doing this, validate ahead-of-time that EV_SEPARATOR records exist for all entries,
        //        and exactly once

        FOREACH_ARRAY(rr, el->records, el->n_records) {
                _cleanup_(json_variant_unrefp) JsonVariant *digests = NULL;
                EventLogRecord *rec = *rr;
                uint32_t bit = UINT32_C(1) << rec->pcr;

                if (!EVENT_LOG_RECORD_IS_FIRMWARE(rec))
                        continue;

                if (!FLAGS_SET(always_mask, bit) &&
                    !(FLAGS_SET(separator_mask, bit) && !FLAGS_SET(separator_seen_mask|action_seen_mask, bit)))
                        continue;

                /* If we hit the separator record, we stop processing the PCRs listed in `separator_mask` */
                if (event_log_record_is_separator(rec)) {
                        separator_seen_mask |= bit;
                        continue;
                }

                /* If we hit the special "Calling EFI Application from Boot Option" action we treat this the
                 * same as a separator here, as that's where firmware passes control to boot loader. Note
                 * that some EFI implementations forget to generate one of them. */
                r = event_log_record_is_action_calling_efi_app(rec);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if event is 'Calling EFI Application from Boot Option' action: %m");
                if (r > 0) {
                        action_seen_mask |= bit;
                        continue;
                }

                LIST_FOREACH(banks, bank, rec->banks) {
                        r = json_variant_append_arrayb(
                                        &digests,
                                        JSON_BUILD_OBJECT(
                                                        JSON_BUILD_PAIR("hashAlg", JSON_BUILD_STRING(tpm2_hash_alg_to_string(bank->algorithm))),
                                                        JSON_BUILD_PAIR("digest", JSON_BUILD_HEX(bank->hash.buffer, bank->hash.size))));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build digests array: %m");
                }

                r = json_variant_append_arrayb(
                                FLAGS_SET(separator_seen_mask, bit) ? &array_late : &array_early,
                                JSON_BUILD_OBJECT(
                                               JSON_BUILD_PAIR("pcr", JSON_BUILD_UNSIGNED(rec->pcr)),
                                               JSON_BUILD_PAIR("digests", JSON_BUILD_VARIANT(digests))));
                if (r < 0)
                        return log_error_errno(r, "Failed to build record array: %m");
        }

        r = write_pcrlock(array_early, default_pcrlock_early_path);
        if (r < 0)
                return r;

        return write_pcrlock(array_late, default_pcrlock_late_path);
}

static int verb_unlock_firmware(int argc, char *argv[], void *userdata) {
        const char *default_pcrlock_early_path, *default_pcrlock_late_path;
        int r;

        if (endswith(argv[0], "firmware-code")) {
                default_pcrlock_early_path = PCRLOCK_FIRMWARE_CODE_EARLY_PATH;
                default_pcrlock_late_path = PCRLOCK_FIRMWARE_CODE_LATE_PATH;
        } else {
                default_pcrlock_early_path = PCRLOCK_FIRMWARE_CONFIG_EARLY_PATH;
                default_pcrlock_late_path = PCRLOCK_FIRMWARE_CONFIG_LATE_PATH;
        }

        r = unlink_pcrlock(default_pcrlock_early_path);
        if (r < 0)
                return r;

        if (arg_pcrlock_path) /* if the path is specified don't delete the same thing twice */
                return 0;

        r = unlink_pcrlock(default_pcrlock_late_path);
        if (r < 0)
                return r;

        return 0;
}

static int verb_lock_machine_id(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *record = NULL, *array = NULL;
        _cleanup_free_ char *word = NULL;
        int r;

        r = pcrextend_machine_id_word(&word);
        if (r < 0)
                return r;

        r = make_pcrlock_record(TPM2_PCR_SYSTEM_IDENTITY /* = 15 */, word, SIZE_MAX, &record);
        if (r < 0)
                return r;

        r = json_variant_new_array(&array, &record, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to create record array: %m");

        return write_pcrlock(array, PCRLOCK_MACHINE_ID_PATH);
}

static int verb_unlock_machine_id(int argc, char *argv[], void *userdata) {
        return unlink_pcrlock(PCRLOCK_MACHINE_ID_PATH);
}

static int pcrlock_file_system_path(const char *normalized_path, char **ret) {
        _cleanup_free_ char *s = NULL;

        assert(normalized_path);

        if (path_equal(normalized_path, "/"))
                s = strdup(PCRLOCK_ROOT_FILE_SYSTEM_PATH);
        else {
                /* We reuse the escaping we use for turning paths into unit names */
                _cleanup_free_ char *escaped = NULL;

                assert(normalized_path[0] == '/');
                assert(normalized_path[1] != '/');

                escaped = unit_name_escape(normalized_path + 1);
                if (!escaped)
                        return log_oom();

                s = strjoin(PCRLOCK_FILE_SYSTEM_PATH_PREFIX, escaped, ".pcrlock");
        }
        if (!s)
                return log_oom();

        *ret = TAKE_PTR(s);
        return 0;
}

static int verb_lock_file_system(int argc, char *argv[], void *userdata) {
        const char* paths[3] = {};
        int r;

        if (argc > 1)
                paths[0] = argv[1];
        else {
                dev_t a, b;
                paths[0] = "/";

                r = get_block_device("/", &a);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device of root file system: %m");

                r = get_block_device("/var", &b);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device of /var/ file system: %m");

                /* if backing device is distinct, then measure /var/ too */
                if (a != b)
                        paths[1] = "/var";

                enable_json_sse();
        }

        STRV_FOREACH(p, paths) {
                _cleanup_free_ char *word = NULL, *normalized_path = NULL, *pcrlock_file = NULL;
                _cleanup_(json_variant_unrefp) JsonVariant *record = NULL, *array = NULL;

                r = pcrextend_file_system_word(*p, &word, &normalized_path);
                if (r < 0)
                        return r;

                r = pcrlock_file_system_path(normalized_path, &pcrlock_file);
                if (r < 0)
                        return r;

                r = make_pcrlock_record(TPM2_PCR_SYSTEM_IDENTITY /* = 15 */, word, SIZE_MAX, &record);
                if (r < 0)
                        return r;

                r = json_variant_new_array(&array, &record, 1);
                if (r < 0)
                        return log_error_errno(r, "Failed to create record array: %m");

                r = write_pcrlock(array, pcrlock_file);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int verb_unlock_file_system(int argc, char *argv[], void *userdata) {
        const char* paths[3] = {};
        int r;

        if (argc > 1)
                paths[0] = argv[1];
        else {
                paths[0] = "/";
                paths[1] = "/var";
        }

        STRV_FOREACH(p, paths) {
                _cleanup_free_ char *normalized_path = NULL, *pcrlock_file = NULL;

                r = chase(*p, NULL, 0, &normalized_path, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to normal path '%s': %m", argv[1]);

                r = pcrlock_file_system_path(normalized_path, &pcrlock_file);
                if (r < 0)
                        return r;

                r = unlink_pcrlock(pcrlock_file);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int verb_lock_pe(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        // FIXME: Maybe also generate a matching EV_EFI_VARIABLE_AUTHORITY records here for each signature that
        //        covers this PE plus its hash, as alternatives under the same component name

        if (argc >= 2) {
                fd = open(argv[1], O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", argv[1]);
        }

        if (arg_pcr_mask == 0)
                arg_pcr_mask = UINT32_C(1) << TPM2_PCR_BOOT_LOADER_CODE;

        for (uint32_t i = 0; i < TPM2_PCRS_MAX; i++) {
                _cleanup_(json_variant_unrefp) JsonVariant *digests = NULL;

                if (!FLAGS_SET(arg_pcr_mask, UINT32_C(1) << i))
                        continue;

                FOREACH_ARRAY(pa, tpm2_hash_algorithms, TPM2_N_HASH_ALGORITHMS) {
                        _cleanup_free_ void *hash = NULL;
                        size_t hash_size;
                        const EVP_MD *md;
                        const char *a;

                        assert_se(a = tpm2_hash_alg_to_string(*pa));
                        assert_se(md = EVP_get_digestbyname(a));

                        r = pe_hash(fd < 0 ? STDIN_FILENO : fd, md, &hash, &hash_size);
                        if (r < 0)
                                return log_error_errno(r, "Failed to hash PE binary: %m");

                        r = json_variant_append_arrayb(&digests,
                                                       JSON_BUILD_OBJECT(
                                                                       JSON_BUILD_PAIR("hashAlg", JSON_BUILD_STRING(a)),
                                                                       JSON_BUILD_PAIR("digest", JSON_BUILD_HEX(hash, hash_size))));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON digest object: %m");
                }

                r = json_variant_append_arrayb(
                                &array,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR("pcr", JSON_BUILD_UNSIGNED(i)),
                                                JSON_BUILD_PAIR("digests", JSON_BUILD_VARIANT(digests))));
                if (r < 0)
                        return log_error_errno(r, "Failed to append record object: %m");
        }

        return write_pcrlock(array, NULL);
}

typedef void* SectionHashArray[_UNIFIED_SECTION_MAX * TPM2_N_HASH_ALGORITHMS];

static void section_hashes_array_done(SectionHashArray *array) {
        assert(array);

        for (size_t i = 0; i < _UNIFIED_SECTION_MAX * TPM2_N_HASH_ALGORITHMS; i++)
                free((*array)[i]);
}

static int verb_lock_uki(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *array = NULL, *pe_digests = NULL;
        _cleanup_(section_hashes_array_done) SectionHashArray section_hashes = {};
        size_t hash_sizes[TPM2_N_HASH_ALGORITHMS];
        _cleanup_close_ int fd = -EBADF;
        int r;

        if (arg_pcr_mask != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "PCR not configurable for UKI lock down.");

        if (argc >= 2) {
                fd = open(argv[1], O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", argv[1]);
        }

        for (size_t i = 0; i < TPM2_N_HASH_ALGORITHMS; i++) {
                _cleanup_free_ void *peh = NULL;
                const EVP_MD *md;
                const char *a;

                assert_se(a = tpm2_hash_alg_to_string(tpm2_hash_algorithms[i]));
                assert_se(md = EVP_get_digestbyname(a));

                r = pe_hash(fd < 0 ? STDIN_FILENO : fd, md, &peh, hash_sizes + i);
                if (r < 0)
                        return log_error_errno(r, "Failed to hash PE binary: %m");

                r = json_variant_append_arrayb(
                                &pe_digests,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR("hashAlg", JSON_BUILD_STRING(a)),
                                                JSON_BUILD_PAIR("digest", JSON_BUILD_HEX(peh, hash_sizes[i]))));
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON digest object: %m");

                r = uki_hash(fd < 0 ? STDIN_FILENO : fd, md, section_hashes + (i * _UNIFIED_SECTION_MAX), hash_sizes + i);
                if (r < 0)
                        return log_error_errno(r, "Failed to UKI hash PE binary: %m");
        }

        r = json_variant_append_arrayb(
                        &array,
                        JSON_BUILD_OBJECT(
                                        JSON_BUILD_PAIR("pcr", JSON_BUILD_UNSIGNED(TPM2_PCR_BOOT_LOADER_CODE)),
                                        JSON_BUILD_PAIR("digests", JSON_BUILD_VARIANT(pe_digests))));
        if (r < 0)
                return log_error_errno(r, "Failed to append record object: %m");

        for (UnifiedSection section = 0; section < _UNIFIED_SECTION_MAX; section++) {
                _cleanup_(json_variant_unrefp) JsonVariant *section_digests = NULL, *record = NULL;

                if (!unified_section_measure(section))
                        continue;

                for (size_t i = 0; i < TPM2_N_HASH_ALGORITHMS; i++) {
                        const char *a;
                        void *hash;

                        hash = section_hashes[i * _UNIFIED_SECTION_MAX + section];
                        if (!hash)
                                continue;

                        assert_se(a = tpm2_hash_alg_to_string(tpm2_hash_algorithms[i]));

                        r = json_variant_append_arrayb(
                                        &section_digests,
                                        JSON_BUILD_OBJECT(
                                                        JSON_BUILD_PAIR("hashAlg", JSON_BUILD_STRING(a)),
                                                        JSON_BUILD_PAIR("digest", JSON_BUILD_HEX(hash, hash_sizes[i]))));
                        if (r < 0)
                                return log_error_errno(r, "Failed to build JSON digest object: %m");
                }

                if (!section_digests)
                        continue;

                /* So we have digests for this section, hence generate a record for the section name first. */
                r = make_pcrlock_record(TPM2_PCR_KERNEL_BOOT /* =11 */, unified_sections[section], strlen(unified_sections[section]) + 1, &record);
                if (r < 0)
                        return r;

                r = json_variant_append_array(&array, record);
                if (r < 0)
                        return log_error_errno(r, "Failed to append JSON record array: %m");

                /* And then append a record for the section contents digests as well */
                r = json_variant_append_arrayb(
                                &array,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR("pcr", JSON_BUILD_UNSIGNED(TPM2_PCR_KERNEL_BOOT /* =11 */)),
                                                JSON_BUILD_PAIR("digests", JSON_BUILD_VARIANT(section_digests))));
                if (r < 0)
                        return log_error_errno(r, "Failed to append record object: %m");
        }

        return write_pcrlock(array, NULL);
}

static int event_log_reduce_to_safe_pcrs(EventLog *el, uint32_t *pcrs) {
        _cleanup_free_ char *dropped = NULL, *kept = NULL;

        assert(el);
        assert(pcrs);

        /* When we compile a new PCR policy we don't want to bind to PCRs which are fishy for one of three
         * reasons:
         *
         * 1. The PCR value doesn't match the event log
         * 2. The event log for the PCR contains measurements we don't know responsible components for
         * 3. The event log for the PCR does not contain measurements for components we know
         *
         * This function checks for the three conditions and drops the PCR from the mask.
         */

        for (uint32_t pcr = 0; pcr < TPM2_PCRS_MAX; pcr++) {

                if (!FLAGS_SET(*pcrs, UINT32_C(1) << pcr))
                        continue;

                if (!event_log_pcr_checks_out(el, el->registers + pcr)) {
                        log_notice("PCR %" PRIu32 " (%s) value does not match event log. Removing from set of PCRs.", pcr, strna(tpm2_pcr_index_to_string(pcr)));
                        goto drop;
                }

                if (!el->registers[pcr].fully_recognized) {
                        log_notice("PCR %" PRIu32 " (%s) event log contains unrecognized measurements. Removing from set of PCRs.", pcr, strna(tpm2_pcr_index_to_string(pcr)));
                        goto drop;
                }

                if (FLAGS_SET(el->missing_component_pcrs, UINT32_C(1) << pcr)) {
                        log_notice("PCR %" PRIu32 " (%s) is touched by component we can't find in event log. Removing from set of PCRs.", pcr, strna(tpm2_pcr_index_to_string(pcr)));
                        goto drop;
                }

                log_info("PCR %" PRIu32 " (%s) matches event log and fully consists of recognized measurements. Including in set of PCRs.", pcr, strna(tpm2_pcr_index_to_string(pcr)));

                if (strextendf_with_separator(&kept, ", ", "%" PRIu32 " (%s)", pcr, tpm2_pcr_index_to_string(pcr)) < 0)
                        return log_oom();

                continue;

        drop:
                *pcrs &= ~(UINT32_C(1) << pcr);

                if (strextendf_with_separator(&dropped, ", ", "%" PRIu32 " (%s)", pcr, tpm2_pcr_index_to_string(pcr)) < 0)
                        return log_oom();
        }

        if (dropped)
                log_notice("PCRs dropped from protection mask: %s", dropped);
        else
                log_debug("No PCRs dropped from protection mask.");

        if (kept)
                log_notice("PCRs in protection mask: %s", kept);
        else
                log_notice("No PCRs kept in protection mask.");

        return 0;
}

static int verb_lock_kernel_cmdline(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *record = NULL, *array = NULL;
        _cleanup_free_ char *cmdline = NULL;
        int r;

        if (argc > 1) {
                if (empty_or_dash(argv[1]))
                        r = read_full_stream(stdin, &cmdline, NULL);
                else
                        r = read_full_file(argv[1], &cmdline, NULL);
        } else
                r = proc_cmdline(&cmdline);
        if (r < 0)
                return log_error_errno(r, "Failed to read cmdline: %m");

        delete_trailing_chars(cmdline, "\n");

        _cleanup_free_ char16_t *u = NULL;
        u = utf8_to_utf16(cmdline, SIZE_MAX);
        if (!u)
                return log_oom();

        r = make_pcrlock_record(TPM2_PCR_KERNEL_INITRD /* = 9 */, u, char16_strlen(u)*2+2, &record);
        if (r < 0)
                return r;

        r = json_variant_new_array(&array, &record, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to create record array: %m");

        r = write_pcrlock(array, PCRLOCK_KERNEL_CMDLINE_PATH);
        if (r < 0)
                return r;

        return 0;
}

static int verb_unlock_kernel_cmdline(int argc, char *argv[], void *userdata) {
        return unlink_pcrlock(PCRLOCK_KERNEL_CMDLINE_PATH);
}

static int verb_lock_kernel_initrd(int argc, char *argv[], void *userdata) {
        _cleanup_(json_variant_unrefp) JsonVariant *record = NULL, *array = NULL;
        _cleanup_free_ void *data = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        size_t size;
        int r;

        if (argc >= 2) {
                f = fopen(argv[1], "re");
                if (!f)
                        return log_error_errno(errno, "Failed to open '%s': %m", argv[1]);
        }

        r = read_full_stream(f ?: stdin, (char**) &data, &size);
        if (r < 0)
                return log_error_errno(r, "Failed to read data from stdin: %m");

        r = make_pcrlock_record(TPM2_PCR_KERNEL_INITRD /* = 9 */, data, size, &record);
        if (r < 0)
                return r;

        r = json_variant_new_array(&array, &record, 1);
        if (r < 0)
                return log_error_errno(r, "Failed to create record array: %m");

        r = write_pcrlock(array, PCRLOCK_KERNEL_INITRD_PATH);
        if (r < 0)
                return r;

        return 0;
}

static int verb_unlock_kernel_initrd(int argc, char *argv[], void *userdata) {
        return unlink_pcrlock(PCRLOCK_KERNEL_INITRD_PATH);
}

static int pcr_prediction_add_result(
                Tpm2PCRPrediction *context,
                Tpm2PCRPredictionResult *result,
                uint32_t pcr,
                const char *path,
                size_t offset) {

        _cleanup_free_ Tpm2PCRPredictionResult *copy = NULL;
        int r;

        assert(context);
        assert(result);

        copy = newdup(Tpm2PCRPredictionResult, result, 1);
        if (!copy)
                return log_oom();

        r = ordered_set_ensure_put(context->results + pcr, &tpm2_pcr_prediction_result_hash_ops, copy);
        if (r == -EEXIST) /* Multiple identical results for the same PCR are totally expected */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to insert result into set: %m");

        log_debug("Added prediction result %u for PCR %" PRIu32 " (path: %s)", ordered_set_size(context->results[pcr]), pcr, strempty(path));

        TAKE_PTR(copy);
        return 0;
}

static const EVP_MD* evp_from_tpm2_alg(uint16_t alg) {
        const char *name;

        name = tpm2_hash_alg_to_string(alg);
        if (!name)
                return NULL;

        return EVP_get_digestbyname(name);
}

static int event_log_component_variant_calculate(
                Tpm2PCRPrediction *context,
                Tpm2PCRPredictionResult *result,
                EventLogComponent *component,
                EventLogComponentVariant *variant,
                uint32_t pcr,
                const char *path) {

        int r;

        assert(context);
        assert(result);
        assert(component);
        assert(variant);

        FOREACH_ARRAY(rr, variant->records, variant->n_records) {
                EventLogRecord *rec = *rr;

                if (rec->pcr != pcr)
                        continue;

                for (size_t i = 0; i < TPM2_N_HASH_ALGORITHMS; i++) {
                        _cleanup_(EVP_MD_CTX_freep) EVP_MD_CTX *md_ctx = NULL;
                        EventLogRecordBank *b;

                        if (result->hash[i].size <= 0) /* already invalidated */
                                continue;

                        b = event_log_record_find_bank(rec, tpm2_hash_algorithms[i]);
                        if (!b) {
                                /* Can't calculate, hence invalidate */
                                result->hash[i] = (TPM2B_DIGEST) {};
                                continue;
                        }

                        md_ctx = EVP_MD_CTX_new();
                        if (!md_ctx)
                                return log_oom();

                        const EVP_MD *md = ASSERT_PTR(evp_from_tpm2_alg(tpm2_hash_algorithms[i]));

                        int sz = EVP_MD_size(md);
                        assert(sz > 0);
                        assert((size_t) sz <= sizeof_field(TPM2B_DIGEST, buffer));

                        assert(sz == tpm2_hash_alg_to_size(tpm2_hash_algorithms[i]));

                        assert(result->hash[i].size == (size_t) sz);
                        assert(b->hash.size == (size_t) sz);

                        if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to initialize message digest.");

                        if (EVP_DigestUpdate(md_ctx, result->hash[i].buffer, sz) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to hash bank value.");

                        if (EVP_DigestUpdate(md_ctx, b->hash.buffer, sz) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to hash data value.");

                        unsigned l = (unsigned) sz;
                        if (EVP_DigestFinal_ex(md_ctx, result->hash[i].buffer, &l) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to finalize message digest.");

                        assert(l == (unsigned) sz);
                }

                /* This is a valid result once we hit the start location */
                if (arg_location_start && strcmp(component->id, arg_location_start) >= 0) {
                        r = pcr_prediction_add_result(context, result, pcr, path, rr - variant->records);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int event_log_predict_pcrs(
                EventLog *el,
                Tpm2PCRPrediction *context,
                Tpm2PCRPredictionResult *parent_result,
                size_t component_index,
                uint32_t pcr,
                const char *path) {

        EventLogComponent *component;
        int count = 0, r;

        assert(el);
        assert(context);
        assert(parent_result);

        /* Check if we reached the end of the components, generate a result, and backtrack */
        if (component_index >= el->n_components ||
            (arg_location_end && strcmp(el->components[component_index]->id, arg_location_end) > 0)) {
                r = pcr_prediction_add_result(context, parent_result, pcr, path, /* offset= */ 0);
                if (r < 0)
                        return r;

                return 1;
        }

        component = ASSERT_PTR(el->components[component_index]);

        FOREACH_ARRAY(ii, component->variants, component->n_variants) {
                _cleanup_free_ Tpm2PCRPredictionResult *result = NULL;
                EventLogComponentVariant *variant = *ii;
                _cleanup_free_ char *subpath = NULL;

                /* Operate on a copy of the result */

                if (path)
                        subpath = strjoin(path, ":", component->id);
                else
                        subpath = strdup(component->id);
                if (!subpath)
                        return log_oom();

                if (!streq(component->id, variant->id))
                        if (!strextend(&subpath, "@", variant->id))
                                return log_oom();

                result = newdup(Tpm2PCRPredictionResult, parent_result, 1);
                if (!result)
                        return log_oom();

                r = event_log_component_variant_calculate(
                                context,
                                result,
                                component,
                                variant,
                                pcr,
                                subpath);
                if (r < 0)
                        return r;

                r = event_log_predict_pcrs(
                                el,
                                context,
                                result,
                                component_index + 1, /* Next component */
                                pcr,
                                subpath);
                if (r < 0)
                        return r;

                count += r;
        }

        return count;
}

static ssize_t event_log_calculate_component_combinations(EventLog *el) {
        ssize_t count = 1;
        assert(el);

        FOREACH_ARRAY(cc, el->components, el->n_components) {
                EventLogComponent *c = *cc;

                /* Overflow check */
                if (c->n_variants > (size_t) (SSIZE_MAX/count))
                        return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Too many component combinations.");

                count *= c->n_variants;
        }

        return count;
}

static int event_log_show_predictions(Tpm2PCRPrediction *context, uint16_t alg) {
        int r;

        assert(context);

        pager_open(arg_pager_flags);

        if (!FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF)) {
                _cleanup_(json_variant_unrefp) JsonVariant *j = NULL;

                for (size_t i = 0; i < TPM2_N_HASH_ALGORITHMS; i++) {
                        _cleanup_(json_variant_unrefp) JsonVariant *aj = NULL;

                        r = tpm2_pcr_prediction_to_json(
                                        context,
                                        tpm2_hash_algorithms[i],
                                        &aj);
                        if (r < 0)
                                return r;

                        if (json_variant_elements(aj) == 0)
                                continue;

                        r = json_variant_set_field(
                                        &j,
                                        tpm2_hash_alg_to_string(tpm2_hash_algorithms[i]),
                                        aj);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add prediction bank to object: %m");
                }

                if (!j) {
                        r = json_variant_new_object(&j, NULL, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocated empty object: %m");
                }

                json_variant_dump(j, arg_json_format_flags, /* f= */ NULL, /* prefix= */ NULL);
                return 0;
        }

        for (uint32_t pcr = 0; pcr < TPM2_PCRS_MAX; pcr++) {
                Tpm2PCRPredictionResult *result;
                if (!FLAGS_SET(context->pcrs, UINT32_C(1) << pcr))
                        continue;

                if (ordered_set_isempty(context->results[pcr])) {
                        printf("No results for PCR %u (%s).\n", pcr, tpm2_pcr_index_to_string(pcr));
                        continue;
                }

                printf("%sResults for PCR %u (%s):%s\n", ansi_underline(), pcr, tpm2_pcr_index_to_string(pcr), ansi_normal());

                ORDERED_SET_FOREACH(result, context->results[pcr]) {

                        _cleanup_free_ char *aa = NULL, *h = NULL;
                        const char *a;

                        TPM2B_DIGEST *hash = tpm2_pcr_prediction_result_get_hash(result, alg);
                        if (!hash)
                                continue;

                        a = ASSERT_PTR(tpm2_hash_alg_to_string(alg));
                        aa = strdup(a);
                        if (!aa)
                                return log_oom();

                        ascii_strlower(aa);

                        h = hexmem(hash->buffer, hash->size);
                        if (!h)
                                return log_oom();

                        printf("  %s%-6s:%s %s\n", ansi_grey(), aa, ansi_normal(), h);
                }
        }

        return 0;
}

static int tpm2_pcr_prediction_run(
                EventLog *el,
                Tpm2PCRPrediction *context) {

        int r;

        assert(el);
        assert(context);

        for (uint32_t pcr = 0; pcr < TPM2_PCRS_MAX; pcr++) {
                _cleanup_free_ Tpm2PCRPredictionResult *result = NULL;

                if (!FLAGS_SET(context->pcrs, UINT32_C(1) << pcr))
                        continue;

                result = new0(Tpm2PCRPredictionResult, 1);
                if (!result)
                        return log_oom();

                for (size_t i = 0; i < TPM2_N_HASH_ALGORITHMS; i++)
                        event_log_initial_pcr_state(el, pcr, tpm2_hash_alg_to_size(tpm2_hash_algorithms[i]), result->hash + i);

                r = event_log_predict_pcrs(
                                el,
                                context,
                                result,
                                /* component_index= */ 0,
                                pcr,
                                /* path= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int verb_predict(int argc, char *argv[], void *userdata) {
        _cleanup_(tpm2_pcr_prediction_done) Tpm2PCRPrediction context = {
                arg_pcr_mask != 0 ? arg_pcr_mask : DEFAULT_PCR_MASK,
        };
        _cleanup_(event_log_freep) EventLog *el = NULL;
        ssize_t count;
        int r;

        r = event_log_load_and_process(&el);
        if (r < 0)
                return r;

        count = event_log_calculate_component_combinations(el);
        if (count < 0)
                return count;

        log_info("%zi combinations of components.", count);

        r = event_log_reduce_to_safe_pcrs(el, &context.pcrs);
        if (r < 0)
                return r;

        r = tpm2_pcr_prediction_run(el, &context);
        if (r < 0)
                return r;

        return event_log_show_predictions(&context, el->primary_algorithm);
}

static int remove_policy_file(const char *path) {
        assert(path);

        if (unlink(path) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to remove policy file '%s': %m", path);
        }

        log_info("Removed policy file '%s'.", path);
        return 1;
}

static int verb_make_policy(int argc, char *argv[], void *userdata) {
        int r;

        /* Here's how this all works: after predicting all possible PCR values for next boot (with
         * alternatives) we'll calculate a policy from it as a combination of PolicyPCR + PolicyOR
         * expressions. This is then stored in an NV index. When a component of the boot process is changed a
         * new prediction is made and the NV index updated (which automatically invalidates any older
         * policies).
         *
         * Whenever we want to lock an encrypted object (for example FDE) against this policy, we'll use a
         * PolicyAuthorizeNV epxression that pins the NV index in the policy, and permits access to any
         * policies matching the current NV index contents.
         *
         * We grant world-readable read access to the NV index. Write access is controlled by a PIN (which we
         * either generate locally or which the user can provide us with) which can also be used for
         * recovery. This PIN is sealed to the TPM and is locked via PolicyAuthorizeNV to the NV index it
         * protects (i.e. we dogfood 🌭 🐶 hard here). This means in order to update such a policy we need
         * the policy to pass.
         *
         * Information about the used NV Index, the SRK of the TPM, the sealed PIN and the current PCR
         * prediction data are stored in a JSON file in /var/lib/. In order to be able to unlock root disks
         * this data must be also copied to the ESP so that it is available to the initrd. The data is not
         * sensitive, as SRK and NV index are pinned by it, and the prediction data must match the NV index
         * to be useful. */

        usec_t start_usec = now(CLOCK_MONOTONIC);

        _cleanup_(event_log_freep) EventLog *el = NULL;
        r = event_log_load_and_process(&el);
        if (r < 0)
                return r;

        _cleanup_(tpm2_pcr_prediction_done) Tpm2PCRPrediction new_prediction = {
                arg_pcr_mask != 0 ? arg_pcr_mask : DEFAULT_PCR_MASK,
        };
        r = event_log_reduce_to_safe_pcrs(el, &new_prediction.pcrs);
        if (r < 0)
                return r;

        usec_t predict_start_usec = now(CLOCK_MONOTONIC);

        r = tpm2_pcr_prediction_run(el, &new_prediction);
        if (r < 0)
                return r;

        log_info("Predicted future PCRs in %s.", FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), predict_start_usec), 1));

        _cleanup_(json_variant_unrefp) JsonVariant *new_prediction_json = NULL;
        r = tpm2_pcr_prediction_to_json(&new_prediction, el->primary_algorithm, &new_prediction_json);
        if (r < 0)
                return r;

        if (DEBUG_LOGGING)
                (void) json_variant_dump(new_prediction_json, JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO, stderr, NULL);

        _cleanup_(tpm2_pcrlock_policy_done) Tpm2PCRLockPolicy old_policy = {};

        r = tpm2_pcrlock_policy_load(arg_pcrlock_path, &old_policy);
        if (r < 0)
                return r;

        bool have_old_policy = r > 0;

        /* When we update the policy the old serializations for NV, SRK, PIN remain the same */
        _cleanup_(iovec_done) struct iovec
                nv_blob = TAKE_STRUCT(old_policy.nv_handle),
                nv_public_blob = TAKE_STRUCT(old_policy.nv_public),
                srk_blob = TAKE_STRUCT(old_policy.srk_handle),
                pin_public = TAKE_STRUCT(old_policy.pin_public),
                pin_private = TAKE_STRUCT(old_policy.pin_private);

        if (have_old_policy) {
                if (arg_nv_index != 0 && old_policy.nv_index != arg_nv_index)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Stored policy references different NV index (0x%x) than specified (0x%x), refusing.", old_policy.nv_index, arg_nv_index);

                if (!arg_force &&
                    old_policy.algorithm == el->primary_algorithm &&
                    tpm2_pcr_prediction_equal(&old_policy.prediction, &new_prediction, el->primary_algorithm)) {
                        log_info("Prediction is identical to current policy, skipping update.");
                        return EXIT_SUCCESS;
                }
        }

        _cleanup_(tpm2_context_unrefp) Tpm2Context *tc = NULL;
        r = tpm2_context_new(NULL, &tc);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate TPM2 context: %m");

        if (!tpm2_supports_command(tc, TPM2_CC_PolicyAuthorizeNV))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "TPM2 does not support PolicyAuthorizeNV command, refusing.");

        _cleanup_(tpm2_handle_freep) Tpm2Handle *srk_handle = NULL;

        if (iovec_is_set(&srk_blob)) {
                r = tpm2_deserialize(
                                tc,
                                srk_blob.iov_base,
                                srk_blob.iov_len,
                                &srk_handle);
                if (r < 0)
                        return log_error_errno(r, "Failed to deserialize SRK TR: %m");
        } else {
                r = tpm2_get_or_create_srk(
                                tc,
                                /* session= */ NULL,
                                /* ret_public= */ NULL,
                                /* ret_name= */ NULL,
                                /* ret_qname= */ NULL,
                                &srk_handle);
                if (r < 0)
                        return log_error_errno(r, "Failed to install SRK: %m");
        }

        _cleanup_(tpm2_handle_freep) Tpm2Handle *encryption_session = NULL;
        r = tpm2_make_encryption_session(
                        tc,
                        srk_handle,
                        /* bind_key= */ &TPM2_HANDLE_NONE,
                        &encryption_session);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate encryption session: %m");

        /* Acquire a recovery PIN, either from the user, or create a randomized one */
        _cleanup_(erase_and_freep) char *pin = NULL;
        if (arg_recovery_pin) {
                r = getenv_steal_erase("PIN", &pin);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire PIN from environment: %m");
                if (r == 0) {
                        _cleanup_(strv_free_erasep) char **l = NULL;

                        r = ask_password_auto(
                                        "Recovery PIN",
                                        /* icon= */ NULL,
                                        /* id= */ "pcrlock-recovery-pin",
                                        /* key_name= */ NULL,
                                        /* credential_name= */ "systemd-pcrlock.recovery-pin",
                                        /* until= */ 0,
                                        /* flags= */ 0,
                                        &l);
                        if (r < 0)
                                return log_error_errno(r, "Failed to query for recovery PIN: %m");

                        if (strv_length(l) != 1)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected a single PIN only.");

                        pin = TAKE_PTR(l[0]);
                        l = mfree(l);
                }

        } else if (!have_old_policy) {
                char rnd[256];

                r = crypto_random_bytes(rnd, sizeof(rnd));
                if (r < 0)
                        return log_error_errno(r, "Failed to generate a randomized recovery PIN: %m");

                (void) base64mem(rnd, sizeof(rnd), &pin);
                explicit_bzero_safe(rnd, sizeof(rnd));
                if (!pin)
                        return log_oom();
        }

        _cleanup_(tpm2_handle_freep) Tpm2Handle *nv_handle = NULL;
        TPM2_HANDLE nv_index = 0;

        if (iovec_is_set(&nv_blob)) {
                r = tpm2_deserialize(tc, nv_blob.iov_base, nv_blob.iov_len, &nv_handle);
                if (r < 0)
                        return log_error_errno(r, "Failed to deserialize NV index TR: %m");

                nv_index = old_policy.nv_index;
        }

        TPM2B_AUTH auth = {};
        CLEANUP_ERASE(auth);

        if (pin) {
                r = tpm2_get_pin_auth(TPM2_ALG_SHA256, pin, &auth);
                if (r < 0)
                        return log_error_errno(r, "Failed to hash PIN: %m");
        } else {
                assert(iovec_is_set(&pin_public));
                assert(iovec_is_set(&pin_private));

                log_debug("Retrieving PIN from sealed data.");

                usec_t pin_start_usec = now(CLOCK_MONOTONIC);

                _cleanup_(iovec_done_erase) struct iovec secret = {};
                for (unsigned attempt = 0;; attempt++) {
                        _cleanup_(tpm2_handle_freep) Tpm2Handle *policy_session = NULL;

                        r = tpm2_make_policy_session(
                                        tc,
                                        srk_handle,
                                        encryption_session,
                                        &policy_session);
                        if (r < 0)
                                return log_error_errno(r, "Failed to allocate policy session: %m");

                        r = tpm2_policy_super_pcr(
                                        tc,
                                        policy_session,
                                        &old_policy.prediction,
                                        old_policy.algorithm);
                        if (r < 0)
                                return log_error_errno(r, "Failed to submit super PCR policy: %m");

                        r = tpm2_policy_authorize_nv(
                                        tc,
                                        policy_session,
                                        nv_handle,
                                        NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to submit AuthorizeNV policy: %m");

                        r = tpm2_unseal_data(
                                        tc,
                                        &pin_public,
                                        &pin_private,
                                        srk_handle,
                                        policy_session,
                                        encryption_session,
                                        &secret);
                        if (r < 0 && (r != -ESTALE || attempt >= 16))
                                return log_error_errno(r, "Failed to unseal PIN: %m");
                        if (r == 0)
                                break;

                        log_debug("Trying again (attempt %u), as PCR values changed during unlock attempt.", attempt+1);
                }

                if (secret.iov_len > sizeof_field(TPM2B_AUTH, buffer))
                        return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Decrypted PIN too large.");

                auth = (TPM2B_AUTH) {
                        .size = secret.iov_len,
                };

                memcpy_safe(auth.buffer, secret.iov_base, secret.iov_len);

                log_info("Retrieved PIN from TPM2 in %s.", FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), pin_start_usec), 1));
        }

        TPM2B_NV_PUBLIC nv_public = {};

        usec_t nv_index_start_usec = now(CLOCK_MONOTONIC);

        if (!iovec_is_set(&nv_blob)) {
                TPM2B_DIGEST recovery_policy_digest = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);
                r = tpm2_calculate_policy_auth_value(&recovery_policy_digest);
                if (r < 0)
                        return log_error_errno(r, "Failed to calculate authentication value policy: %m");

                log_debug("Allocating NV index to write PCR policy to...");
                r = tpm2_define_policy_nv_index(
                                tc,
                                encryption_session,
                                arg_nv_index,
                                &recovery_policy_digest,
                                pin,
                                &auth,
                                &nv_index,
                                &nv_handle,
                                &nv_public);
                if (r == -EEXIST)
                        return log_error_errno(r, "NV index 0x%" PRIx32 " already allocated.", arg_nv_index);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate NV index: %m");
        }

        r = tpm2_set_auth_binary(tc, nv_handle, &auth);
        if (r < 0)
                return log_error_errno(r, "Failed to set authentication value on NV index: %m");

        _cleanup_(tpm2_handle_freep) Tpm2Handle *policy_session = NULL;
        r = tpm2_make_policy_session(
                        tc,
                        srk_handle,
                        encryption_session,
                        &policy_session);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate policy session: %m");

        r = tpm2_policy_auth_value(
                        tc,
                        policy_session,
                        /* ret_policy_digest= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to submit authentication value policy: %m");

        log_debug("Calculating new PCR policy to write...");
        TPM2B_DIGEST new_super_pcr_policy_digest = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);

        usec_t pcr_policy_start_usec = now(CLOCK_MONOTONIC);

        r = tpm2_calculate_policy_super_pcr(
                        &new_prediction,
                        el->primary_algorithm,
                        &new_super_pcr_policy_digest);
        if (r < 0)
                return log_error_errno(r, "Failed to calculate super PCR policy: %m");

        log_info("Calculated new PCR policy in %s.", FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), pcr_policy_start_usec), 1));

        log_debug("Writing new PCR policy to NV index...");
        r = tpm2_write_policy_nv_index(
                        tc,
                        policy_session,
                        nv_index,
                        nv_handle,
                        &new_super_pcr_policy_digest);
        if (r < 0)
                return log_error_errno(r, "Failed to write to NV index: %m");

        log_info("Updated NV index in %s.", FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), nv_index_start_usec), 1));

        assert(iovec_is_set(&pin_public) == iovec_is_set(&pin_private));
        if (!iovec_is_set(&pin_public)) {
                TPM2B_DIGEST authnv_policy_digest  = TPM2B_DIGEST_MAKE(NULL, TPM2_SHA256_DIGEST_SIZE);

                r = tpm2_calculate_policy_authorize_nv(&nv_public, &authnv_policy_digest);
                if (r < 0)
                        return log_error_errno(r, "Failed to calculate AuthorizeNV policy: %m");

                struct iovec data = {
                        .iov_base = auth.buffer,
                        .iov_len = auth.size,
                };

                usec_t pin_seal_start_usec = now(CLOCK_MONOTONIC);

                log_debug("Sealing PIN to NV index policy...");
                r = tpm2_seal_data(
                                tc,
                                &data,
                                srk_handle,
                                encryption_session,
                                &authnv_policy_digest,
                                &pin_public,
                                &pin_private);
                if (r < 0)
                        return log_error_errno(r, "Failed to seal PIN to NV auth policy: %m");

                log_info("Sealed PIN in %s.", FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), pin_seal_start_usec), 1));
        }

        if (!iovec_is_set(&nv_blob)) {
                r = tpm2_serialize(tc, nv_handle, &nv_blob.iov_base, &nv_blob.iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to serialize NV index TR: %m");
        }

        if (!iovec_is_set(&srk_blob)) {
                r = tpm2_serialize(tc, srk_handle, &srk_blob.iov_base, &srk_blob.iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to serialize SRK index TR: %m");
        }

        if (!iovec_is_set(&nv_public_blob)) {
                r = tpm2_marshal_nv_public(&nv_public, &nv_public_blob.iov_base, &nv_public_blob.iov_len);
                if (r < 0)
                        return log_error_errno(r, "Failed to marshal NV public area: %m");
        }

        _cleanup_(json_variant_unrefp) JsonVariant *new_configuration_json = NULL;
        r = json_build(&new_configuration_json,
                       JSON_BUILD_OBJECT(
                                       JSON_BUILD_PAIR_STRING("pcrBank", tpm2_hash_alg_to_string(el->primary_algorithm)),
                                       JSON_BUILD_PAIR_VARIANT("pcrValues", new_prediction_json),
                                       JSON_BUILD_PAIR_INTEGER("nvIndex", nv_index),
                                       JSON_BUILD_PAIR_IOVEC_BASE64("nvHandle", &nv_blob),
                                       JSON_BUILD_PAIR_IOVEC_BASE64("nvPublic", &nv_public_blob),
                                       JSON_BUILD_PAIR_IOVEC_BASE64("srkHandle", &srk_blob),
                                       JSON_BUILD_PAIR_IOVEC_BASE64("pinPublic", &pin_public),
                                       JSON_BUILD_PAIR_IOVEC_BASE64("pinPrivate", &pin_private)));
        if (r < 0)
                return log_error_errno(r, "Failed to generate JSON: %m");

        _cleanup_free_ char *text = NULL;
        r = json_variant_format(new_configuration_json, 0, &text);
        if (r < 0)
                return log_error_errno(r, "Failed to format new configuration to JSON: %m");

        const char *path = arg_pcrlock_path ?: (in_initrd() ? "/run/systemd/pcrlock.json" : "/var/lib/systemd/pcrlock.json");
        r = write_string_file(path, text, WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_SYNC|WRITE_STRING_FILE_MKDIR_0755);
        if (r < 0)
                return log_error_errno(r, "Failed to write new configuration to '%s': %m", path);

        if (!arg_pcrlock_path && !in_initrd()) {
                r = remove_policy_file("/run/systemd/pcrlock.json");
                if (r < 0)
                        return r;
        }

        log_info("Written new policy to '%s' and digest to TPM2 NV index 0x%" PRIu32 ".", path, nv_index);

        log_info("Overall time spent: %s", FORMAT_TIMESPAN(usec_sub_unsigned(now(CLOCK_MONOTONIC), start_usec), 1));

        return 0;
}

static int undefine_policy_nv_index(
                uint32_t nv_index,
                const struct iovec *nv_blob,
                const struct iovec *srk_blob) {
        int r;

        assert(nv_blob);
        assert(srk_blob);

        _cleanup_(tpm2_context_unrefp) Tpm2Context *tc = NULL;
        r = tpm2_context_new(NULL, &tc);
        if (r < 0)
                return r;

        _cleanup_(tpm2_handle_freep) Tpm2Handle *srk_handle = NULL;
        r = tpm2_deserialize(
                        tc,
                        srk_blob->iov_base,
                        srk_blob->iov_len,
                        &srk_handle);
                if (r < 0)
                        return log_error_errno(r, "Failed to deserialize SRK TR: %m");

        _cleanup_(tpm2_handle_freep) Tpm2Handle *nv_handle = NULL;
        r = tpm2_deserialize(
                        tc,
                        nv_blob->iov_base,
                        nv_blob->iov_len,
                        &nv_handle);
                if (r < 0)
                        return log_error_errno(r, "Failed to deserialize NV TR: %m");

        _cleanup_(tpm2_handle_freep) Tpm2Handle *encryption_session = NULL;
        r = tpm2_make_encryption_session(
                        tc,
                        srk_handle,
                        /* bind_key= */ &TPM2_HANDLE_NONE,
                        &encryption_session);
        if (r < 0)
                return r;

        r = tpm2_undefine_policy_nv_index(
                        tc,
                        encryption_session,
                        nv_index,
                        nv_handle);
        if (r < 0)
                return r;

        log_info("Removed NV index 0x%x", nv_index);
        return 0;
}

static int verb_remove_policy(int argc, char *argv[], void *userdata) {
        int r;

        _cleanup_(tpm2_pcrlock_policy_done) Tpm2PCRLockPolicy policy = {};
        r = tpm2_pcrlock_policy_load(arg_policy_path, &policy);
        if (r == 0) {
                log_info("No policy found.");
                return 0;
        }

        if (r < 0)
                log_notice("Failed to load old policy file, assuming it is corrupted, removing.");
        else {
                r = undefine_policy_nv_index(policy.nv_index, &policy.nv_handle, &policy.srk_handle);
                if (r < 0)
                        log_notice("Failed to remove NV index, assuming data out of date, removing policy file.");
        }

        if (arg_policy_path) {
                r = remove_policy_file(arg_policy_path);
                if (r < 0)
                        return r;

                return 0;
        } else {
                int ret = 0;

                RET_GATHER(ret, remove_policy_file("/var/lib/systemd/pcrlock.json"));
                RET_GATHER(ret, remove_policy_file("/run/systemd/pcrlock.json"));

                return ret;
        }
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-pcrlock", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s  [OPTIONS...] COMMAND ...\n"
               "\n%5$sManage a TPM2 PCR lock.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  log                         Show measurement log\n"
               "  cel                         Show measurement log in TCG CEL-JSON format\n"
               "  list-components             List defined .pcrlock components\n"
               "  predict                     Predict PCR values\n"
               "  make-policy                 Predict PCR values and generate TPM2 policy from it\n"
               "  remove-policy               Remove TPM2 policy\n"
               "\n%3$sProtections:%4$s\n"
               "  lock-firmware-code          Generate a .pcrlock file from current firmware code\n"
               "  unlock-firmware-code        Remove .pcrlock file for firmware code\n"
               "  lock-firmware-config        Generate a .pcrlock file from current firmware configuration\n"
               "  unlock-firmware-config      Remove .pcrlock file for firmware configuration\n"
               "  lock-secureboot-policy      Generate a .pcrlock file from current SecureBoot policy\n"
               "  unlock-secureboot-policy    Remove .pcrlock file for SecureBoot policy\n"
               "  lock-secureboot-authority   Generate a .pcrlock file from current SecureBoot authority\n"
               "  unlock-secureboot-authority Remove .pcrlock file for SecureBoot authority\n"
               "  lock-gpt [DISK]             Generate a .pcrlock file from GPT header\n"
               "  unlock-gpt                  Remove .pcrlock file for GPT header\n"
               "  lock-pe [BINARY]            Generate a .pcrlock file from PE binary\n"
               "  unlock-pe                   Remove .pcrlock file for PE binary\n"
               "  lock-uki [UKI]              Generate a .pcrlock file from UKI PE binary\n"
               "  unlock-uki                  Remove .pcrlock file for UKI PE binary\n"
               "  lock-machine-id             Generate a .pcrlock file from current machine ID\n"
               "  unlock-machine-id           Remove .pcrlock file for machine ID\n"
               "  lock-file-system [PATH]     Generate a .pcrlock file from current root fs + /var/\n"
               "  unlock-file-system [PATH]   Remove .pcrlock file for root fs + /var/\n"
               "  lock-kernel-cmdline [FILE]  Generate a .pcrlock file from kernel command line\n"
               "  unlock-kernel-cmdline       Remove .pcrlock file for kernel command line\n"
               "  lock-kernel-initrd FILE     Generate a .pcrlock file from an initrd file\n"
               "  unlock-kernel-initrd        Remove .pcrlock file for an initrd file\n"
               "  lock-raw [FILE]             Generate a .pcrlock file from raw data\n"
               "  unlock-raw                  Remove .pcrlock file for raw data\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                   Show this help\n"
               "     --version                Print version\n"
               "     --no-pager               Do not pipe output into a pager\n"
               "     --json=pretty|short|off  Generate JSON output\n"
               "     --raw-description        Show raw firmware record data as description in table\n"
               "     --pcr=NR                 Generate .pcrlock for specified PCR\n"
               "     --nv-index=NUMBER        Use the specified NV index, instead of a random one\n"
               "     --components=PATH        Directory to read .pcrlock files from\n"
               "     --location=STRING[:STRING]\n"
               "                              Do not process components beyond this component name\n"
               "     --recovery-pin=yes       Ask for a recovery PIN\n"
               "     --pcrlock=PATH           .pcrlock file to write expected PCR measurement to\n"
               "     --policy=PATH            JSON file to write policy output to\n"
               "     --force                  Write policy even if it matches existing policy\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_JSON,
                ARG_RAW_DESCRIPTION,
                ARG_PCR,
                ARG_NV_INDEX,
                ARG_COMPONENTS,
                ARG_LOCATION,
                ARG_RECOVERY_PIN,
                ARG_PCRLOCK,
                ARG_POLICY,
                ARG_FORCE,
        };

        static const struct option options[] = {
                { "help",            no_argument,       NULL, 'h'                 },
                { "version",         no_argument,       NULL, ARG_VERSION         },
                { "no-pager",        no_argument,       NULL, ARG_NO_PAGER        },
                { "json",            required_argument, NULL, ARG_JSON            },
                { "raw-description", no_argument,       NULL, ARG_RAW_DESCRIPTION },
                { "pcr",             required_argument, NULL, ARG_PCR             },
                { "nv-index",        required_argument, NULL, ARG_NV_INDEX        },
                { "components",      required_argument, NULL, ARG_COMPONENTS      },
                { "location",        required_argument, NULL, ARG_LOCATION        },
                { "recovery-pin",    required_argument, NULL, ARG_RECOVERY_PIN    },
                { "pcrlock",         required_argument, NULL, ARG_PCRLOCK         },
                { "policy",          required_argument, NULL, ARG_POLICY          },
                { "force",           no_argument,       NULL, ARG_FORCE           },
                {}
        };

        bool auto_location = true;
        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "h", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                case ARG_RAW_DESCRIPTION:
                        arg_raw_description = true;
                        break;

                case ARG_PCR: {
                        r = tpm2_parse_pcr_argument_to_mask(optarg, &arg_pcr_mask);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse PCR specification: %s", optarg);

                        break;
                }

                case ARG_NV_INDEX:
                        if (isempty(optarg))
                                arg_nv_index = 0;
                        else {
                                uint32_t u;

                                r = safe_atou32_full(optarg, 16, &u);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to parse --nv-index= argument: %s", optarg);

                                if (u < TPM2_NV_INDEX_FIRST || u > TPM2_NV_INDEX_LAST)
                                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Argument for --nv-index= outside of valid range 0x%" PRIx32 "…0x%"  PRIx32 ": 0x%" PRIx32,
                                                               TPM2_NV_INDEX_FIRST, TPM2_NV_INDEX_LAST, u);

                                arg_nv_index = u;
                        }
                        break;

                case ARG_COMPONENTS: {
                        _cleanup_free_ char *p = NULL;

                        r = parse_path_argument(optarg, /* suppress_root= */ false, &p);
                        if (r < 0)
                                return r;

                        r = strv_consume(&arg_components, TAKE_PTR(p));
                        if (r < 0)
                                return log_oom();

                        break;
                }

                case ARG_LOCATION: {
                        _cleanup_free_ char *start = NULL, *end = NULL;
                        const char *e;

                        auto_location = false;

                        if (isempty(optarg)) {
                                arg_location_start = mfree(arg_location_start);
                                arg_location_end = mfree(arg_location_end);
                                break;
                        }

                        e = strchr(optarg, ':');
                        if (e) {
                                start = strndup(optarg, e - optarg);
                                if (!start)
                                        return log_oom();

                                end = strdup(e + 1);
                                if (!end)
                                        return log_oom();
                        } else {
                                start = strdup(optarg);
                                if (!start)
                                        return log_oom();

                                end = strdup(optarg);
                                if (!end)
                                        return log_oom();
                        }

                        if (!filename_is_valid(start))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Location string invalid, refusing: %s", start);
                        if (!filename_is_valid(end))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Location string invalid, refusing: %s", end);

                        free_and_replace(arg_location_start, start);
                        free_and_replace(arg_location_end, end);
                        break;
                }

                case ARG_RECOVERY_PIN:
                        r = parse_boolean_argument("--recovery-pin", optarg, &arg_recovery_pin);
                        if (r < 0)
                                return r;
                        break;

                case ARG_PCRLOCK:
                        if (empty_or_dash(optarg))
                                arg_pcrlock_path = mfree(arg_pcrlock_path);
                        else {
                                r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_pcrlock_path);
                                if (r < 0)
                                        return r;
                        }

                        arg_pcrlock_auto = false;
                        break;

                case ARG_POLICY:
                        if (empty_or_dash(optarg))
                                arg_policy_path = mfree(arg_policy_path);
                        else {
                                r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_policy_path);
                                if (r < 0)
                                        return r;
                        }

                        break;

                case ARG_FORCE:
                        arg_force = true;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (auto_location) {
                assert(!arg_location_start);
                assert(!arg_location_end);

                arg_location_start = strdup("760-");
                if (!arg_location_start)
                        return log_oom();

                arg_location_end = strdup("940-");
                if (!arg_location_end)
                        return log_oom();
        }

        return 1;
}

static int pcrlock_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "help",                        VERB_ANY, VERB_ANY, 0,            help                             },
                { "log",                         VERB_ANY, 1,        VERB_DEFAULT, verb_show_log                    },
                { "cel",                         VERB_ANY, 1,        0,            verb_show_cel                    },
                { "list-components",             VERB_ANY, 1,        0,            verb_list_components             },
                { "predict",                     VERB_ANY, 1,        0,            verb_predict                     },
                { "lock-firmware-code",          VERB_ANY, 2,        0,            verb_lock_firmware               },
                { "unlock-firmware-code",        VERB_ANY, 1,        0,            verb_unlock_firmware             },
                { "lock-firmware-config",        VERB_ANY, 2,        0,            verb_lock_firmware               },
                { "unlock-firmware-config",      VERB_ANY, 1,        0,            verb_unlock_firmware             },
                { "lock-secureboot-policy",      VERB_ANY, 1,        0,            verb_lock_secureboot_policy      },
                { "unlock-secureboot-policy",    VERB_ANY, 1,        0,            verb_unlock_secureboot_policy    },
                { "lock-secureboot-authority",   VERB_ANY, 1,        0,            verb_lock_secureboot_authority   },
                { "unlock-secureboot-authority", VERB_ANY, 1,        0,            verb_unlock_secureboot_authority },
                { "lock-gpt",                    VERB_ANY, 2,        0,            verb_lock_gpt                    },
                { "unlock-gpt",                  VERB_ANY, 1,        0,            verb_unlock_gpt                  },
                { "lock-pe",                     VERB_ANY, 2,        0,            verb_lock_pe                     },
                { "unlock-pe",                   VERB_ANY, 1,        0,            verb_unlock_simple               },
                { "lock-uki",                    VERB_ANY, 2,        0,            verb_lock_uki                    },
                { "unlock-uki",                  VERB_ANY, 1,        0,            verb_unlock_simple               },
                { "lock-machine-id",             VERB_ANY, 1,        0,            verb_lock_machine_id             },
                { "unlock-machine-id",           VERB_ANY, 1,        0,            verb_unlock_machine_id           },
                { "lock-file-system",            VERB_ANY, 2,        0,            verb_lock_file_system            },
                { "unlock-file-system",          VERB_ANY, 2,        0,            verb_unlock_file_system          },
                { "lock-kernel-cmdline",         VERB_ANY, 2,        0,            verb_lock_kernel_cmdline         },
                { "unlock-kernel-cmdline",       VERB_ANY, 1,        0,            verb_unlock_kernel_cmdline       },
                { "lock-kernel-initrd",          VERB_ANY, 2,        0,            verb_lock_kernel_initrd          },
                { "unlock-kernel-initrd",        VERB_ANY, 1,        0,            verb_unlock_kernel_initrd        },
                { "lock-raw",                    VERB_ANY, 2,        0,            verb_lock_raw                    },
                { "unlock-raw",                  VERB_ANY, 1,        0,            verb_unlock_simple               },
                { "make-policy",                 VERB_ANY, 1,        0,            verb_make_policy                 },
                { "remove-policy",               VERB_ANY, 1,        0,            verb_remove_policy               },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_show_color(true);
        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return pcrlock_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
