/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "efi-api.h"
#include "efivars.h"
#include "fd-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "utf8.h"

#if ENABLE_EFI

#define LOAD_OPTION_ACTIVE            0x00000001
#define MEDIA_DEVICE_PATH                   0x04
#define MEDIA_HARDDRIVE_DP                  0x01
#define MEDIA_FILEPATH_DP                   0x04
#define SIGNATURE_TYPE_GUID                 0x02
#define MBR_TYPE_EFI_PARTITION_TABLE_HEADER 0x02
#define END_DEVICE_PATH_TYPE                0x7f
#define END_ENTIRE_DEVICE_PATH_SUBTYPE      0xff

#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI UINT64_C(0x0000000000000001)

#define boot_option__contents                   \
        {                                       \
                uint32_t attr;                  \
                uint16_t path_len;              \
                uint16_t title[];               \
        }

struct boot_option boot_option__contents;
struct boot_option__packed boot_option__contents _packed_;
assert_cc(offsetof(struct boot_option, title) == offsetof(struct boot_option__packed, title));
/* sizeof(struct boot_option) != sizeof(struct boot_option__packed), so
 * the *size* of the structure should not be used anywhere below. */

struct drive_path {
        uint32_t part_nr;
        uint64_t part_start;
        uint64_t part_size;
        char signature[16];
        uint8_t mbr_type;
        uint8_t signature_type;
} _packed_;

#define device_path__contents                           \
        {                                               \
                uint8_t type;                           \
                uint8_t sub_type;                       \
                uint16_t length;                        \
                union {                                 \
                        uint16_t path[0];               \
                        struct drive_path drive;        \
                };                                      \
        }

struct device_path device_path__contents;
struct device_path__packed device_path__contents _packed_;
assert_cc(sizeof(struct device_path) == sizeof(struct device_path__packed));

int efi_reboot_to_firmware_supported(void) {
        _cleanup_free_ void *v = NULL;
        static int cache = -1;
        uint64_t b;
        size_t s;
        int r;

        if (cache > 0)
                return 0;
        if (cache == 0)
                return -EOPNOTSUPP;

        if (!is_efi_boot())
                goto not_supported;

        r = efi_get_variable(EFI_GLOBAL_VARIABLE(OsIndicationsSupported), NULL, &v, &s);
        if (r == -ENOENT)
                goto not_supported; /* variable doesn't exist? it's not supported then */
        if (r < 0)
                return r;
        if (s != sizeof(uint64_t))
                return -EINVAL;

        b = *(uint64_t*) v;
        if (!(b & EFI_OS_INDICATIONS_BOOT_TO_FW_UI))
                goto not_supported; /* bit unset? it's not supported then */

        cache = 1;
        return 0;

not_supported:
        cache = 0;
        return -EOPNOTSUPP;
}

static int get_os_indications(uint64_t *ret) {
        static struct stat cache_stat = {};
        _cleanup_free_ void *v = NULL;
        static uint64_t cache;
        struct stat new_stat;
        size_t s;
        int r;

        assert(ret);

        /* Let's verify general support first */
        r = efi_reboot_to_firmware_supported();
        if (r < 0)
                return r;

        /* stat() the EFI variable, to see if the mtime changed. If it did we need to cache again. */
        if (stat(EFIVAR_PATH(EFI_GLOBAL_VARIABLE(OsIndications)), &new_stat) < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* Doesn't exist? Then we can exit early (also see below) */
                *ret = 0;
                return 0;

        } else if (stat_inode_unmodified(&new_stat, &cache_stat)) {
                /* inode didn't change, we can return the cached value */
                *ret = cache;
                return 0;
        }

        r = efi_get_variable(EFI_GLOBAL_VARIABLE(OsIndications), NULL, &v, &s);
        if (r == -ENOENT) {
                /* Some firmware implementations that do support OsIndications and report that with
                 * OsIndicationsSupported will remove the OsIndications variable when it is unset. Let's
                 * pretend it's 0 then, to hide this implementation detail. Note that this call will return
                 * -ENOENT then only if the support for OsIndications is missing entirely, as determined by
                 * efi_reboot_to_firmware_supported() above. */
                *ret = 0;
                return 0;
        }
        if (r < 0)
                return r;
        if (s != sizeof(uint64_t))
                return -EINVAL;

        cache_stat = new_stat;
        *ret = cache = *(uint64_t *)v;
        return 0;
}

int efi_get_reboot_to_firmware(void) {
        int r;
        uint64_t b;

        r = get_os_indications(&b);
        if (r < 0)
                return r;

        return !!(b & EFI_OS_INDICATIONS_BOOT_TO_FW_UI);
}

int efi_set_reboot_to_firmware(bool value) {
        int r;
        uint64_t b, b_new;

        r = get_os_indications(&b);
        if (r < 0)
                return r;

        b_new = UPDATE_FLAG(b, EFI_OS_INDICATIONS_BOOT_TO_FW_UI, value);

        /* Avoid writing to efi vars store if we can due to firmware bugs. */
        if (b != b_new)
                return efi_set_variable(EFI_GLOBAL_VARIABLE(OsIndications), &b_new, sizeof(uint64_t));

        return 0;
}

static ssize_t utf16_size(const uint16_t *s, size_t buf_len_bytes) {
        size_t l = 0;

        /* Returns the size of the string in bytes without the terminating two zero bytes */

        while (l < buf_len_bytes / sizeof(uint16_t)) {
                if (s[l] == 0)
                        return (l + 1) * sizeof(uint16_t);
                l++;
        }

        return -EINVAL; /* The terminator was not found */
}

int efi_get_boot_option(
                uint16_t id,
                char **ret_title,
                sd_id128_t *ret_part_uuid,
                char **ret_path,
                bool *ret_active) {

        char variable[STRLEN(EFI_GLOBAL_VARIABLE_STR("Boot")) + 4 + 1];
        _cleanup_free_ uint8_t *buf = NULL;
        size_t l;
        struct boot_option *header;
        ssize_t title_size;
        _cleanup_free_ char *s = NULL, *p = NULL;
        sd_id128_t p_uuid = SD_ID128_NULL;
        int r;

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        xsprintf(variable, EFI_GLOBAL_VARIABLE_STR("Boot%04X"), id);
        r = efi_get_variable(variable, NULL, (void **)&buf, &l);
        if (r < 0)
                return r;
        if (l < offsetof(struct boot_option, title))
                return -ENOENT;

        header = (struct boot_option *)buf;
        title_size = utf16_size(header->title, l - offsetof(struct boot_option, title));
        if (title_size < 0)
                return title_size;

        if (ret_title) {
                s = utf16_to_utf8(header->title, title_size);
                if (!s)
                        return -ENOMEM;
        }

        if (header->path_len > 0) {
                uint8_t *dbuf;
                size_t dnext, doff;

                doff = offsetof(struct boot_option, title) + title_size;
                dbuf = buf + doff;
                if (header->path_len > l - doff)
                        return -EINVAL;

                dnext = 0;
                while (dnext < header->path_len) {
                        struct device_path *dpath;

                        dpath = (struct device_path *)(dbuf + dnext);
                        if (dpath->length < 4)
                                break;

                        /* Type 0x7F – End of Hardware Device Path, Sub-Type 0xFF – End Entire Device Path */
                        if (dpath->type == END_DEVICE_PATH_TYPE && dpath->sub_type == END_ENTIRE_DEVICE_PATH_SUBTYPE)
                                break;

                        dnext += dpath->length;

                        /* Type 0x04 – Media Device Path */
                        if (dpath->type != MEDIA_DEVICE_PATH)
                                continue;

                        /* Sub-Type 1 – Hard Drive */
                        if (dpath->sub_type == MEDIA_HARDDRIVE_DP) {
                                /* 0x02 – GUID Partition Table */
                                if (dpath->drive.mbr_type != MBR_TYPE_EFI_PARTITION_TABLE_HEADER)
                                        continue;

                                /* 0x02 – GUID signature */
                                if (dpath->drive.signature_type != SIGNATURE_TYPE_GUID)
                                        continue;

                                if (ret_part_uuid)
                                        p_uuid = efi_guid_to_id128(dpath->drive.signature);
                                continue;
                        }

                        /* Sub-Type 4 – File Path */
                        if (dpath->sub_type == MEDIA_FILEPATH_DP && !p && ret_path) {
                                p = utf16_to_utf8(dpath->path, dpath->length-4);
                                if (!p)
                                        return  -ENOMEM;

                                efi_tilt_backslashes(p);
                                continue;
                        }
                }
        }

        if (ret_title)
                *ret_title = TAKE_PTR(s);
        if (ret_part_uuid)
                *ret_part_uuid = p_uuid;
        if (ret_path)
                *ret_path = TAKE_PTR(p);
        if (ret_active)
                *ret_active = header->attr & LOAD_OPTION_ACTIVE;

        return 0;
}

static void to_utf16(uint16_t *dest, const char *src) {
        int i;

        for (i = 0; src[i] != '\0'; i++)
                dest[i] = src[i];
        dest[i] = '\0';
}

static uint16_t *tilt_slashes(uint16_t *s) {
        for (uint16_t *p = s; *p; p++)
                if (*p == '/')
                        *p = '\\';

        return s;
}

int efi_add_boot_option(
                uint16_t id,
                const char *title,
                uint32_t part,
                uint64_t pstart,
                uint64_t psize,
                sd_id128_t part_uuid,
                const char *path) {

        size_t size, title_len, path_len;
        _cleanup_free_ char *buf = NULL;
        struct boot_option *option;
        struct device_path *devicep;
        char variable[STRLEN(EFI_GLOBAL_VARIABLE_STR("Boot")) + 4 + 1];

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        title_len = (strlen(title)+1) * 2;
        path_len = (strlen(path)+1) * 2;

        buf = malloc0(offsetof(struct boot_option, title) + title_len +
                      sizeof(struct drive_path) +
                      sizeof(struct device_path) + path_len);
        if (!buf)
                return -ENOMEM;

        /* header */
        option = (struct boot_option *)buf;
        option->attr = LOAD_OPTION_ACTIVE;
        option->path_len = offsetof(struct device_path, drive) + sizeof(struct drive_path) +
                           offsetof(struct device_path, path) + path_len +
                           offsetof(struct device_path, path);
        to_utf16(option->title, title);
        size = offsetof(struct boot_option, title) + title_len;

        /* partition info */
        devicep = (struct device_path *)(buf + size);
        devicep->type = MEDIA_DEVICE_PATH;
        devicep->sub_type = MEDIA_HARDDRIVE_DP;
        devicep->length = offsetof(struct device_path, drive) + sizeof(struct drive_path);
        memcpy(&devicep->drive.part_nr, &part, sizeof(uint32_t));
        memcpy(&devicep->drive.part_start, &pstart, sizeof(uint64_t));
        memcpy(&devicep->drive.part_size, &psize, sizeof(uint64_t));
        efi_id128_to_guid(part_uuid, devicep->drive.signature);
        devicep->drive.mbr_type = MBR_TYPE_EFI_PARTITION_TABLE_HEADER;
        devicep->drive.signature_type = SIGNATURE_TYPE_GUID;
        size += devicep->length;

        /* path to loader */
        devicep = (struct device_path *)(buf + size);
        devicep->type = MEDIA_DEVICE_PATH;
        devicep->sub_type = MEDIA_FILEPATH_DP;
        devicep->length = offsetof(struct device_path, path) + path_len;
        to_utf16(devicep->path, path);
        tilt_slashes(devicep->path);
        size += devicep->length;

        /* end of path */
        devicep = (struct device_path *)(buf + size);
        devicep->type = END_DEVICE_PATH_TYPE;
        devicep->sub_type = END_ENTIRE_DEVICE_PATH_SUBTYPE;
        devicep->length = offsetof(struct device_path, path);
        size += devicep->length;

        xsprintf(variable, EFI_GLOBAL_VARIABLE_STR("Boot%04X"), id);
        return efi_set_variable(variable, buf, size);
}

int efi_remove_boot_option(uint16_t id) {
        char variable[STRLEN(EFI_GLOBAL_VARIABLE_STR("Boot")) + 4 + 1];

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        xsprintf(variable, EFI_GLOBAL_VARIABLE_STR("Boot%04X"), id);
        return efi_set_variable(variable, NULL, 0);
}

int efi_get_boot_order(uint16_t **ret_order) {
        _cleanup_free_ void *buf = NULL;
        size_t l;
        int r;

        assert(ret_order);

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = efi_get_variable(EFI_GLOBAL_VARIABLE(BootOrder), NULL, &buf, &l);
        if (r < 0)
                return r;

        if (l <= 0)
                return -ENOENT;

        if (l % sizeof(uint16_t) > 0 ||
            l / sizeof(uint16_t) > INT_MAX)
                return -EINVAL;

        *ret_order = TAKE_PTR(buf);
        return (int) (l / sizeof(uint16_t));
}

int efi_set_boot_order(const uint16_t *order, size_t n) {

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        return efi_set_variable(EFI_GLOBAL_VARIABLE(BootOrder), order, n * sizeof(uint16_t));
}

static int boot_id_hex(const char s[static 4]) {
        int id = 0;

        assert(s);

        for (int i = 0; i < 4; i++)
                if (s[i] >= '0' && s[i] <= '9')
                        id |= (s[i] - '0') << (3 - i) * 4;
                else if (s[i] >= 'A' && s[i] <= 'F')
                        id |= (s[i] - 'A' + 10) << (3 - i) * 4;
                else
                        return -EINVAL;

        return id;
}

int efi_get_boot_options(uint16_t **ret_options) {
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ uint16_t *list = NULL;
        int count = 0;

        assert(ret_options);

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        dir = opendir(EFIVAR_PATH("."));
        if (!dir)
                return -errno;

        FOREACH_DIRENT(de, dir, return -errno) {
                int id;

                if (!strneq(de->d_name, "Boot", 4))
                        continue;

                if (strlen(de->d_name) != 45)
                        continue;

                if (!streq(de->d_name + 8, EFI_GLOBAL_VARIABLE_STR("")))  /* generate variable suffix using macro */
                        continue;

                id = boot_id_hex(de->d_name + 4);
                if (id < 0)
                        continue;

                if (!GREEDY_REALLOC(list, count + 1))
                        return -ENOMEM;

                list[count++] = id;
        }

        typesafe_qsort(list, count, cmp_uint16);

        *ret_options = TAKE_PTR(list);

        return count;
}

bool efi_has_tpm2(void) {
        static int cache = -1;

        /* Returns whether the system has a TPM2 chip which is known to the EFI firmware. */

        if (cache >= 0)
                return cache;

        /* First, check if we are on an EFI boot at all. */
        if (!is_efi_boot()) {
                cache = 0;
                return cache;
        }

        /* Then, check if the ACPI table "TPM2" exists, which is the TPM2 event log table, see:
         * https://trustedcomputinggroup.org/wp-content/uploads/TCG_ACPIGeneralSpecification_v1.20_r8.pdf
         * This table exists whenever the firmware is hooked up to TPM2. */
        cache = access("/sys/firmware/acpi/tables/TPM2", F_OK) >= 0;
        if (cache)
                return cache;

        if (errno != ENOENT)
                log_debug_errno(errno, "Unable to test whether /sys/firmware/acpi/tables/TPM2 exists, assuming it doesn't: %m");

        /* As the last try, check if the EFI firmware provides the EFI_TCG2_FINAL_EVENTS_TABLE
         * stored in EFI configuration table, see:
         * https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf
         */
        cache = access("/sys/kernel/security/tpm0/binary_bios_measurements", F_OK) >= 0;
        if (!cache && errno != ENOENT)
                log_debug_errno(errno, "Unable to test whether /sys/kernel/security/tpm0/binary_bios_measurements exists, assuming it doesn't: %m");

        return cache;
}

#endif

struct efi_guid {
        uint32_t u1;
        uint16_t u2;
        uint16_t u3;
        uint8_t u4[8];
} _packed_;

sd_id128_t efi_guid_to_id128(const void *guid) {
        const struct efi_guid *uuid = ASSERT_PTR(guid); /* cast is safe, because struct efi_guid is packed */
        sd_id128_t id128;

        id128.bytes[0] = (uuid->u1 >> 24) & 0xff;
        id128.bytes[1] = (uuid->u1 >> 16) & 0xff;
        id128.bytes[2] = (uuid->u1 >> 8) & 0xff;
        id128.bytes[3] = uuid->u1 & 0xff;

        id128.bytes[4] = (uuid->u2 >> 8) & 0xff;
        id128.bytes[5] = uuid->u2 & 0xff;

        id128.bytes[6] = (uuid->u3 >> 8) & 0xff;
        id128.bytes[7] = uuid->u3 & 0xff;

        memcpy(&id128.bytes[8], uuid->u4, sizeof(uuid->u4));

        return id128;
}

void efi_id128_to_guid(sd_id128_t id, void *ret_guid) {
        assert(ret_guid);

        struct efi_guid uuid = {
                .u1 = id.bytes[0] << 24 | id.bytes[1] << 16 | id.bytes[2] << 8 | id.bytes[3],
                .u2 = id.bytes[4] << 8 | id.bytes[5],
                .u3 = id.bytes[6] << 8 | id.bytes[7],
        };
        memcpy(uuid.u4, id.bytes+8, sizeof(uuid.u4));
        memcpy(ret_guid, &uuid, sizeof(uuid));
}
