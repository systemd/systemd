/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "efi-efivars.h"
#include "efi-log.h"
#include "efi-string.h"
#include "next-boot.h"
#include "strv.h"
#include "util.h"

/* Attribute flags of EFI_LOAD_OPTION, see UEFI spec, section 3.1.3 "Load Options" */
#define LOAD_OPTION_ACTIVE UINT32_C(0x00000001)
#define LOAD_OPTION_HIDDEN UINT32_C(0x00000008)

/* The description prefix of the boot options we create. We recognize our own boot options by this, and
 * reuse them, so that we do not accumulate them. */
#define NEXT_BOOT_DESCRIPTION_PREFIX u"[Next] "

/* The fixed size header of an EFI_LOAD_OPTION, i.e. the contents of a Boot#### EFI variable. It is followed
 * by the NUL-terminated description string, the device path list (FilePathListLength bytes), and the
 * optional data, which takes up the rest of the variable. */
typedef struct {
        uint32_t Attributes;
        uint16_t FilePathListLength;
} _packed_ LoadOptionHeader;

static bool parse_boot_option_name(const char16_t *name, uint16_t *ret) {
        assert(name);
        assert(ret);

        /* Parses a "Boot####" variable name, where #### are exactly four hexadecimal digits. */

        const char16_t *e = startswith(name, u"Boot");
        if (!e)
                return false;

        uint16_t n = 0;
        for (size_t i = 0; i < 4; i++) {
                char16_t c = e[i];
                unsigned v;

                if (c >= '0' && c <= '9')
                        v = c - '0';
                else if (c >= 'A' && c <= 'F')
                        v = c - 'A' + 10;
                else if (c >= 'a' && c <= 'f')
                        v = c - 'a' + 10;
                else
                        return false;

                n = (n << 4) | v;
        }

        if (e[4] != '\0')
                return false;

        *ret = n;
        return true;
}

static const HARDDRIVE_DEVICE_PATH *device_path_find_hard_drive(const EFI_DEVICE_PATH *dp) {
        assert(dp);

        for (; !device_path_is_end(dp); dp = device_path_next_node(dp))
                if (dp->Type == MEDIA_DEVICE_PATH &&
                    dp->SubType == MEDIA_HARDDRIVE_DP &&
                    dp->Length >= sizeof(HARDDRIVE_DEVICE_PATH))
                        return (const HARDDRIVE_DEVICE_PATH *) dp;

        return NULL;
}

static bool hard_drive_equal(const HARDDRIVE_DEVICE_PATH *a, const HARDDRIVE_DEVICE_PATH *b) {
        assert(a);
        assert(b);

        if (a->PartitionNumber != b->PartitionNumber ||
            a->SignatureType != b->SignatureType)
                return false;

        switch (a->SignatureType) {

        case SIGNATURE_TYPE_GUID:
                return memcmp(a->Signature, b->Signature, sizeof(a->Signature)) == 0;

        case SIGNATURE_TYPE_MBR:
                /* MBR signatures are 32bit only, the rest of the field is unused. */
                return memcmp(a->Signature, b->Signature, sizeof(uint32_t)) == 0;

        default:
                /* Without a signature we have no reliable way to identify the partition */
                return false;
        }
}

static char16_t *file_path_node_to_path(const EFI_DEVICE_PATH *node) {
        assert(node);
        assert(node->Type == MEDIA_DEVICE_PATH);
        assert(node->SubType == MEDIA_FILEPATH_DP);

        /* Returns a normalized, aligned copy of the path string in a file path device path node, or NULL
         * if the node is not properly NUL terminated. */

        size_t n = node->Length - offsetof(FILEPATH_DEVICE_PATH, PathName);
        if (n < sizeof(char16_t) || n % sizeof(char16_t) != 0)
                return NULL;

        char16_t *p = xmemdup(((const FILEPATH_DEVICE_PATH *) node)->PathName, n);
        if (p[n / sizeof(char16_t) - 1] != '\0') {
                free(p);
                return NULL;
        }

        convert_efi_path(p);
        return p;
}

typedef struct LoadOption {
        char16_t *description;              /* aligned copy */
        const EFI_DEVICE_PATH *device_path; /* points into the parsed buffer */
        const uint8_t *optional_data;       /* ditto */
        size_t optional_data_size;
} LoadOption;

static void load_option_done(LoadOption *o) {
        assert(o);
        o->description = mfree(o->description);
}

static bool load_option_parse(const void *data, size_t size, LoadOption *ret) {
        assert(data || size == 0);
        assert(ret);

        if (size < sizeof(LoadOptionHeader))
                return false;

        const LoadOptionHeader *h = data;
        const uint8_t *d = (const uint8_t *) data + sizeof(LoadOptionHeader), *p = d,
                *e = (const uint8_t *) data + size;

        /* Find the end of the NUL-terminated description string. Note that it is not necessarily aligned. */
        for (;; p += sizeof(char16_t)) {
                if ((size_t) (e - p) < sizeof(char16_t))
                        return false;
                if (p[0] == 0 && p[1] == 0)
                        break;
        }
        p += sizeof(char16_t);

        if ((size_t) (e - p) < h->FilePathListLength)
                return false;

        /* The FilePathList may contain multiple device paths, but only the first one is the one the
         * firmware boots. */
        const EFI_DEVICE_PATH *dp = (const EFI_DEVICE_PATH *) p;
        if (!device_path_is_valid(dp, h->FilePathListLength))
                return false;

        *ret = (LoadOption) {
                .description = xmemdup(d, p - d),
                .device_path = dp,
                .optional_data = p + h->FilePathListLength,
                .optional_data_size = e - (p + h->FilePathListLength),
        };
        return true;
}

static bool load_option_is_ours(const LoadOption *o) {
        assert(o);
        return startswith(o->description, NEXT_BOOT_DESCRIPTION_PREFIX);
}

static bool load_option_matches(
                const LoadOption *o,
                const EFI_DEVICE_PATH *target,
                const char16_t *target_path,
                const char16_t *options) {

        assert(o);
        assert(target);
        assert(target_path);

        /* Checks whether the load option refers to the same file on the same partition as the specified
         * device path. Note that firmware and OS installers typically write "short-form" device paths
         * (i.e. ones that start with the hard drive media node), hence we match on the partition, not on
         * the full device path.
         *
         * If options are specified, the optional data of the load option (which the firmware passes to the
         * invoked binary as load options) must match them too. If no options are specified, the optional
         * data is not checked, so that we can reuse boot options OS installers created for themselves
         * (e.g. the one Windows creates for its boot manager carries some opaque optional data). */

        if (options) {
                size_t l = strsize16(options);
                if (o->optional_data_size != l || memcmp(o->optional_data, options, l) != 0)
                        return false;
        }

        _cleanup_free_ EFI_DEVICE_PATH *dp_device = NULL, *target_device = NULL;
        const EFI_DEVICE_PATH *dp_file, *target_file;
        if (device_path_split_file_path(o->device_path, &dp_device, &dp_file) != EFI_SUCCESS)
                return false;
        if (device_path_split_file_path(target, &target_device, &target_file) != EFI_SUCCESS)
                return false;

        const HARDDRIVE_DEVICE_PATH *target_hd = device_path_find_hard_drive(target_device);
        if (target_hd) {
                const HARDDRIVE_DEVICE_PATH *dp_hd = device_path_find_hard_drive(dp_device);
                if (!dp_hd || !hard_drive_equal(target_hd, dp_hd))
                        return false;
        } else {
                /* Not a partition? Then insist on a full device path match. */
                size_t l = device_path_size(target_device);
                if (device_path_size(dp_device) != l || memcmp(dp_device, target_device, l) != 0)
                        return false;
        }

        _cleanup_free_ char16_t *path = file_path_node_to_path(dp_file);
        if (!path)
                return false;

        return strcaseeq16(path, target_path);
}

static EFI_STATUS write_boot_option(
                uint16_t n,
                const char16_t *description,
                const EFI_DEVICE_PATH *target,
                const char16_t *target_path,
                const char16_t *options) {

        EFI_STATUS err;

        assert(description);
        assert(target);
        assert(target_path);

        size_t description_size = strsize16(description),
                dp_size = device_path_size(target),
                options_size = options ? strsize16(options) : 0;
        if (dp_size > UINT16_MAX)
                return log_error_status(EFI_INVALID_PARAMETER, "Device path of %ls too long.", target_path);

        /* The optional data is passed by the firmware to the invoked binary as load options, encoded the
         * same way as we pass them when chainloading, i.e. as NUL-terminated UTF-16 string. The option is
         * marked hidden, since it is only intended to be used via BootNext, not to be shown in the
         * firmware's boot menu. */
        size_t size = sizeof(LoadOptionHeader) + description_size + dp_size + options_size;
        _cleanup_free_ uint8_t *data = xmalloc(size);
        *(LoadOptionHeader *) data = (LoadOptionHeader) {
                .Attributes = LOAD_OPTION_ACTIVE | LOAD_OPTION_HIDDEN,
                .FilePathListLength = dp_size,
        };
        uint8_t *q = mempcpy(data + sizeof(LoadOptionHeader), description, description_size);
        q = mempcpy(q, target, dp_size);
        if (options)
                memcpy(q, options, options_size);

        _cleanup_free_ char16_t *name = xasprintf("Boot%04X", n);
        err = efivar_set_raw(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), name, data, size, EFI_VARIABLE_NON_VOLATILE);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to write boot option %ls for %ls: %m", name, target_path);

        log_debug("Wrote boot option %ls for %ls.", name, target_path);
        return EFI_SUCCESS;
}

static EFI_STATUS find_or_create_boot_option(
                const EFI_DEVICE_PATH *target,
                const char16_t *target_path,
                const char16_t *options,
                const char16_t *title,
                uint16_t *ret) {

        EFI_STATUS err;

        assert(target);
        assert(target_path);
        assert(title);
        assert(ret);

        /* Picks a boot option to use with BootNext. In order of preference:
         *
         * 1. An existing boot option that matches what we need (i.e. either one the OS installer created for
         *    itself, or one we created earlier for the same file and options).
         * 2. A boot option we created earlier for something else (recognizable by its description prefix),
         *    which we overwrite.
         * 3. A newly created boot option in the first free slot.
         *
         * In the latter two cases (and if the matching option is one of ours) the description is set to
         * the prefix followed by the title. We do not add our boot options to BootOrder, they are only
         * intended to be used via BootNext. */

        _cleanup_free_ char16_t *description = xasprintf("%ls%ls", NEXT_BOOT_DESCRIPTION_PREFIX, title);

        _cleanup_strv_free_ char16_t **names = NULL;
        err = efivar_get_names(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), &names);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to enumerate EFI variables: %m");

        /* Bitmap of Boot#### numbers that are already taken */
        _cleanup_free_ uint8_t *used = xcalloc((UINT16_MAX + 1) / 8);
        bool have_ours = false;
        uint16_t ours = 0;

        STRV_FOREACH(name, names) {
                uint16_t n;

                if (!parse_boot_option_name(*name, &n))
                        continue;

                used[n / 8] |= 1U << (n % 8);

                _cleanup_free_ void *data = NULL;
                size_t size;
                err = efivar_get_raw(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), *name, &data, &size);
                if (err != EFI_SUCCESS) {
                        log_debug_status(err, "Failed to read EFI variable %ls, ignoring: %m", *name);
                        continue;
                }

                _cleanup_(load_option_done) LoadOption o = {};
                if (!load_option_parse(data, size, &o)) {
                        log_debug("Failed to parse boot option %ls, ignoring.", *name);
                        continue;
                }

                if (load_option_matches(&o, target, target_path, options)) {
                        log_debug("Found matching boot option %ls for %ls.", *name, target_path);

                        /* Update the description of our own boot options, if the title changed */
                        if (load_option_is_ours(&o) && !streq16(o.description, description)) {
                                err = write_boot_option(n, description, target, target_path, options);
                                if (err != EFI_SUCCESS)
                                        return err;
                        }

                        *ret = n;
                        return EFI_SUCCESS;
                }

                if (!have_ours && load_option_is_ours(&o)) {
                        have_ours = true;
                        ours = n;
                }
        }

        if (have_ours) {
                err = write_boot_option(ours, description, target, target_path, options);
                if (err != EFI_SUCCESS)
                        return err;

                *ret = ours;
                return EFI_SUCCESS;
        }

        for (size_t n = 0; n <= UINT16_MAX; n++) {
                if (used[n / 8] & (1U << (n % 8)))
                        continue;

                err = write_boot_option(n, description, target, target_path, options);
                if (err != EFI_SUCCESS)
                        return err;

                *ret = n;
                return EFI_SUCCESS;
        }

        return log_error_status(EFI_OUT_OF_RESOURCES, "No free boot option slot available.");
}

EFI_STATUS next_boot_image(
                EFI_HANDLE device,
                const char16_t *path,
                const char16_t *options,
                const char16_t *title) {

        EFI_STATUS err;

        assert(device);
        assert(path);

        /* Boots the specified EFI binary not by chainloading it, but by finding (or creating) a matching
         * Boot#### firmware boot option, setting BootNext to it, and rebooting. This means the binary is
         * invoked directly by the firmware, which is useful for OSes that bind secrets to TPM PCR 4, which
         * would otherwise change whenever the boot loader is updated. If options is non-NULL it is passed
         * to the binary as load options. Only returns on failure. */

        _cleanup_free_ EFI_DEVICE_PATH *dp = NULL;
        err = make_file_device_path(device, path, &dp);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to make device path for %ls: %m", path);

        _cleanup_free_ char16_t *normalized = xstrdup16(path);
        convert_efi_path(normalized);

        uint16_t n;
        err = find_or_create_boot_option(dp, normalized, options, title ?: normalized, &n);
        if (err != EFI_SUCCESS)
                return err;

        err = efivar_set_raw(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"BootNext", &n, sizeof(n), EFI_VARIABLE_NON_VOLATILE);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to set BootNext EFI variable: %m");

        log_debug("Set BootNext to Boot%04X, rebooting.", n);
        RT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
        assert_not_reached();
}
