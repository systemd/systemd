/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "efi-loader.h"
#include "efivars.h"
#include "fd-util.h"
#include "io-util.h"
#include "parse-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "utf8.h"
#include "virt.h"

#if ENABLE_EFI

#define LOAD_OPTION_ACTIVE            0x00000001
#define MEDIA_DEVICE_PATH                   0x04
#define MEDIA_HARDDRIVE_DP                  0x01
#define MEDIA_FILEPATH_DP                   0x04
#define SIGNATURE_TYPE_GUID                 0x02
#define MBR_TYPE_EFI_PARTITION_TABLE_HEADER 0x02
#define END_DEVICE_PATH_TYPE                0x7f
#define END_ENTIRE_DEVICE_PATH_SUBTYPE      0xff
#define EFI_OS_INDICATIONS_BOOT_TO_FW_UI    0x0000000000000001

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

        r = efi_get_variable(EFI_VENDOR_GLOBAL, "OsIndicationsSupported", NULL, &v, &s);
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
        _cleanup_free_ char *fn = NULL;
        static uint64_t cache;
        struct stat new_stat;
        size_t s;
        int r;

        assert(ret);

        /* Let's verify general support first */
        r = efi_reboot_to_firmware_supported();
        if (r < 0)
                return r;

        fn = efi_variable_path(EFI_VENDOR_GLOBAL, "OsIndications");
        if (!fn)
                return -ENOMEM;

        /* stat() the EFI variable, to see if the mtime changed. If it did we need to cache again. */
        if (stat(fn, &new_stat) < 0) {
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

        r = efi_get_variable(EFI_VENDOR_GLOBAL, "OsIndications", NULL, &v, &s);
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
                return efi_set_variable(EFI_VENDOR_GLOBAL, "OsIndications", &b_new, sizeof(uint64_t));

        return 0;
}

static ssize_t utf16_size(const uint16_t *s, size_t buf_len_bytes) {
        size_t l = 0;

        /* Returns the size of the string in bytes without the terminating two zero bytes */

        if (buf_len_bytes % sizeof(uint16_t) != 0)
                return -EINVAL;

        while (l < buf_len_bytes / sizeof(uint16_t)) {
                if (s[l] == 0)
                        return (l + 1) * sizeof(uint16_t);
                l++;
        }

        return -EINVAL; /* The terminator was not found */
}

struct guid {
        uint32_t u1;
        uint16_t u2;
        uint16_t u3;
        uint8_t u4[8];
} _packed_;

static void efi_guid_to_id128(const void *guid, sd_id128_t *id128) {
        uint32_t u1;
        uint16_t u2, u3;
        const struct guid *uuid = guid;

        memcpy(&u1, &uuid->u1, sizeof(uint32_t));
        id128->bytes[0] = (u1 >> 24) & 0xff;
        id128->bytes[1] = (u1 >> 16) & 0xff;
        id128->bytes[2] = (u1 >> 8) & 0xff;
        id128->bytes[3] = u1 & 0xff;
        memcpy(&u2, &uuid->u2, sizeof(uint16_t));
        id128->bytes[4] = (u2 >> 8) & 0xff;
        id128->bytes[5] = u2 & 0xff;
        memcpy(&u3, &uuid->u3, sizeof(uint16_t));
        id128->bytes[6] = (u3 >> 8) & 0xff;
        id128->bytes[7] = u3 & 0xff;
        memcpy(&id128->bytes[8], uuid->u4, sizeof(uuid->u4));
}

int efi_get_boot_option(
                uint16_t id,
                char **title,
                sd_id128_t *part_uuid,
                char **path,
                bool *active) {

        char boot_id[9];
        _cleanup_free_ uint8_t *buf = NULL;
        size_t l;
        struct boot_option *header;
        ssize_t title_size;
        _cleanup_free_ char *s = NULL, *p = NULL;
        sd_id128_t p_uuid = SD_ID128_NULL;
        int r;

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        xsprintf(boot_id, "Boot%04X", id);
        r = efi_get_variable(EFI_VENDOR_GLOBAL, boot_id, NULL, (void **)&buf, &l);
        if (r < 0)
                return r;
        if (l < offsetof(struct boot_option, title))
                return -ENOENT;

        header = (struct boot_option *)buf;
        title_size = utf16_size(header->title, l - offsetof(struct boot_option, title));
        if (title_size < 0)
                return title_size;

        if (title) {
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

                                if (part_uuid)
                                        efi_guid_to_id128(dpath->drive.signature, &p_uuid);
                                continue;
                        }

                        /* Sub-Type 4 – File Path */
                        if (dpath->sub_type == MEDIA_FILEPATH_DP && !p && path) {
                                p = utf16_to_utf8(dpath->path, dpath->length-4);
                                if (!p)
                                        return  -ENOMEM;

                                efi_tilt_backslashes(p);
                                continue;
                        }
                }
        }

        if (title)
                *title = TAKE_PTR(s);
        if (part_uuid)
                *part_uuid = p_uuid;
        if (path)
                *path = TAKE_PTR(p);
        if (active)
                *active = header->attr & LOAD_OPTION_ACTIVE;

        return 0;
}

static void to_utf16(uint16_t *dest, const char *src) {
        int i;

        for (i = 0; src[i] != '\0'; i++)
                dest[i] = src[i];
        dest[i] = '\0';
}

static void id128_to_efi_guid(sd_id128_t id, void *guid) {
        struct guid uuid = {
                .u1 = id.bytes[0] << 24 | id.bytes[1] << 16 | id.bytes[2] << 8 | id.bytes[3],
                .u2 = id.bytes[4] << 8 | id.bytes[5],
                .u3 = id.bytes[6] << 8 | id.bytes[7],
        };
        memcpy(uuid.u4, id.bytes+8, sizeof(uuid.u4));
        memcpy(guid, &uuid, sizeof(uuid));
}

static uint16_t *tilt_slashes(uint16_t *s) {
        uint16_t *p;

        for (p = s; *p; p++)
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
        char boot_id[9];

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
        id128_to_efi_guid(part_uuid, devicep->drive.signature);
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

        xsprintf(boot_id, "Boot%04X", id);
        return efi_set_variable(EFI_VENDOR_GLOBAL, boot_id, buf, size);
}

int efi_remove_boot_option(uint16_t id) {
        char boot_id[9];

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        xsprintf(boot_id, "Boot%04X", id);
        return efi_set_variable(EFI_VENDOR_GLOBAL, boot_id, NULL, 0);
}

int efi_get_boot_order(uint16_t **order) {
        _cleanup_free_ void *buf = NULL;
        size_t l;
        int r;

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = efi_get_variable(EFI_VENDOR_GLOBAL, "BootOrder", NULL, &buf, &l);
        if (r < 0)
                return r;

        if (l <= 0)
                return -ENOENT;

        if (l % sizeof(uint16_t) > 0 ||
            l / sizeof(uint16_t) > INT_MAX)
                return -EINVAL;

        *order = TAKE_PTR(buf);
        return (int) (l / sizeof(uint16_t));
}

int efi_set_boot_order(uint16_t *order, size_t n) {

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        return efi_set_variable(EFI_VENDOR_GLOBAL, "BootOrder", order, n * sizeof(uint16_t));
}

static int boot_id_hex(const char s[static 4]) {
        int id = 0, i;

        assert(s);

        for (i = 0; i < 4; i++)
                if (s[i] >= '0' && s[i] <= '9')
                        id |= (s[i] - '0') << (3 - i) * 4;
                else if (s[i] >= 'A' && s[i] <= 'F')
                        id |= (s[i] - 'A' + 10) << (3 - i) * 4;
                else
                        return -EINVAL;

        return id;
}

static int cmp_uint16(const uint16_t *a, const uint16_t *b) {
        return CMP(*a, *b);
}

int efi_get_boot_options(uint16_t **options) {
        _cleanup_closedir_ DIR *dir = NULL;
        _cleanup_free_ uint16_t *list = NULL;
        struct dirent *de;
        size_t alloc = 0;
        int count = 0;

        assert(options);

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        dir = opendir("/sys/firmware/efi/efivars/");
        if (!dir)
                return -errno;

        FOREACH_DIRENT(de, dir, return -errno) {
                int id;

                if (strncmp(de->d_name, "Boot", 4) != 0)
                        continue;

                if (strlen(de->d_name) != 45)
                        continue;

                if (strcmp(de->d_name + 8, "-8be4df61-93ca-11d2-aa0d-00e098032b8c") != 0)
                        continue;

                id = boot_id_hex(de->d_name + 4);
                if (id < 0)
                        continue;

                if (!GREEDY_REALLOC(list, alloc, count + 1))
                        return -ENOMEM;

                list[count++] = id;
        }

        typesafe_qsort(list, count, cmp_uint16);

        *options = TAKE_PTR(list);

        return count;
}

static int read_usec(sd_id128_t vendor, const char *name, usec_t *u) {
        _cleanup_free_ char *j = NULL;
        int r;
        uint64_t x = 0;

        assert(name);
        assert(u);

        r = efi_get_variable_string(EFI_VENDOR_LOADER, name, &j);
        if (r < 0)
                return r;

        r = safe_atou64(j, &x);
        if (r < 0)
                return r;

        *u = x;
        return 0;
}

int efi_loader_get_boot_usec(usec_t *firmware, usec_t *loader) {
        uint64_t x, y;
        int r;

        assert(firmware);
        assert(loader);

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = read_usec(EFI_VENDOR_LOADER, "LoaderTimeInitUSec", &x);
        if (r < 0)
                return log_debug_errno(r, "Failed to read LoaderTimeInitUSec: %m");

        r = read_usec(EFI_VENDOR_LOADER, "LoaderTimeExecUSec", &y);
        if (r < 0)
                return log_debug_errno(r, "Failed to read LoaderTimeExecUSec: %m");

        if (y == 0 || y < x || y - x > USEC_PER_HOUR)
                return log_debug_errno(SYNTHETIC_ERRNO(EIO),
                                       "Bad LoaderTimeInitUSec=%"PRIu64", LoaderTimeExecUSec=%" PRIu64"; refusing.",
                                       x, y);

        *firmware = x;
        *loader = y;

        return 0;
}

int efi_loader_get_device_part_uuid(sd_id128_t *u) {
        _cleanup_free_ char *p = NULL;
        int r, parsed[16];

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderDevicePartUUID", &p);
        if (r < 0)
                return r;

        if (sscanf(p, SD_ID128_UUID_FORMAT_STR,
                   &parsed[0], &parsed[1], &parsed[2], &parsed[3],
                   &parsed[4], &parsed[5], &parsed[6], &parsed[7],
                   &parsed[8], &parsed[9], &parsed[10], &parsed[11],
                   &parsed[12], &parsed[13], &parsed[14], &parsed[15]) != 16)
                return -EIO;

        if (u) {
                unsigned i;

                for (i = 0; i < ELEMENTSOF(parsed); i++)
                        u->bytes[i] = parsed[i];
        }

        return 0;
}

int efi_loader_get_entries(char ***ret) {
        _cleanup_free_ char16_t *entries = NULL;
        _cleanup_strv_free_ char **l = NULL;
        size_t size, i, start;
        int r;

        assert(ret);

        if (!is_efi_boot())
                return -EOPNOTSUPP;

        r = efi_get_variable(EFI_VENDOR_LOADER, "LoaderEntries", NULL, (void**) &entries, &size);
        if (r < 0)
                return r;

        /* The variable contains a series of individually NUL terminated UTF-16 strings. */

        for (i = 0, start = 0;; i++) {
                _cleanup_free_ char *decoded = NULL;
                bool end;

                /* Is this the end of the variable's data? */
                end = i * sizeof(char16_t) >= size;

                /* Are we in the middle of a string? (i.e. not at the end of the variable, nor at a NUL terminator?) If
                 * so, let's go to the next entry. */
                if (!end && entries[i] != 0)
                        continue;

                /* We reached the end of a string, let's decode it into UTF-8 */
                decoded = utf16_to_utf8(entries + start, (i - start) * sizeof(char16_t));
                if (!decoded)
                        return -ENOMEM;

                if (efi_loader_entry_name_valid(decoded)) {
                        r = strv_consume(&l, TAKE_PTR(decoded));
                        if (r < 0)
                                return r;
                } else
                        log_debug("Ignoring invalid loader entry '%s'.", decoded);

                /* We reached the end of the variable */
                if (end)
                        break;

                /* Continue after the NUL byte */
                start = i + 1;
        }

        *ret = TAKE_PTR(l);
        return 0;
}

int efi_loader_get_features(uint64_t *ret) {
        _cleanup_free_ void *v = NULL;
        size_t s;
        int r;

        if (!is_efi_boot()) {
                *ret = 0;
                return 0;
        }

        r = efi_get_variable(EFI_VENDOR_LOADER, "LoaderFeatures", NULL, &v, &s);
        if (r == -ENOENT) {
                _cleanup_free_ char *info = NULL;

                /* The new (v240+) LoaderFeatures variable is not supported, let's see if it's systemd-boot at all */
                r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderInfo", &info);
                if (r < 0) {
                        if (r != -ENOENT)
                                return r;

                        /* Variable not set, definitely means not systemd-boot */

                } else if (first_word(info, "systemd-boot")) {

                        /* An older systemd-boot version. Let's hardcode the feature set, since it was pretty
                         * static in all its versions. */

                        *ret = EFI_LOADER_FEATURE_CONFIG_TIMEOUT |
                                EFI_LOADER_FEATURE_ENTRY_DEFAULT |
                                EFI_LOADER_FEATURE_ENTRY_ONESHOT;

                        return 0;
                }

                /* No features supported */
                *ret = 0;
                return 0;
        }
        if (r < 0)
                return r;

        if (s != sizeof(uint64_t))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "LoaderFeatures EFI variable doesn't have the right size.");

        memcpy(ret, v, sizeof(uint64_t));
        return 0;
}

int efi_loader_get_config_timeout_one_shot(usec_t *ret) {
        _cleanup_free_ char *v = NULL, *fn = NULL;
        static struct stat cache_stat = {};
        struct stat new_stat;
        static usec_t cache;
        uint64_t sec;
        int r;

        assert(ret);

        fn = efi_variable_path(EFI_VENDOR_LOADER, "LoaderConfigTimeoutOneShot");
        if (!fn)
                return -ENOMEM;

        /* stat() the EFI variable, to see if the mtime changed. If it did we need to cache again. */
        if (stat(fn, &new_stat) < 0)
                return -errno;

        if (stat_inode_unmodified(&new_stat, &cache_stat)) {
                *ret = cache;
                return 0;
        }

        r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderConfigTimeoutOneShot", &v);
        if (r < 0)
                return r;

        r = safe_atou64(v, &sec);
        if (r < 0)
                return r;
        if (sec > USEC_INFINITY / USEC_PER_SEC)
                return -ERANGE;

        cache_stat = new_stat;
        *ret = cache = sec * USEC_PER_SEC; /* return in µs */
        return 0;
}

int efi_loader_update_entry_one_shot_cache(char **cache, struct stat *cache_stat) {
        _cleanup_free_ char *fn = NULL, *v = NULL;
        struct stat new_stat;
        int r;

        assert(cache);
        assert(cache_stat);

        fn = efi_variable_path(EFI_VENDOR_LOADER, "LoaderEntryOneShot");
        if (!fn)
                return -ENOMEM;

        /* stat() the EFI variable, to see if the mtime changed. If it did we need to cache again. */
        if (stat(fn, &new_stat) < 0)
                return -errno;

        if (stat_inode_unmodified(&new_stat, cache_stat))
                return 0;

        r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntryOneShot", &v);
        if (r < 0)
                return r;

        if (!efi_loader_entry_name_valid(v))
                return -EINVAL;

        *cache_stat = new_stat;
        free_and_replace(*cache, v);

        return 0;
}

bool efi_has_tpm2(void) {
        static int cache = -1;

        /* Returns whether the system has a TPM2 chip which is known to the EFI firmware. */

        if (cache < 0) {

                /* First, check if we are on an EFI boot at all. */
                if (!is_efi_boot())
                        cache = false;
                else {
                        /* Then, check if the ACPI table "TPM2" exists, which is the TPM2 event log table, see:
                         * https://trustedcomputinggroup.org/wp-content/uploads/TCG_ACPIGeneralSpecification_v1.20_r8.pdf
                         * This table exists whenever the firmware is hooked up to TPM2. */
                        cache = access("/sys/firmware/acpi/tables/TPM2", F_OK) >= 0;
                        if (!cache && errno != ENOENT)
                                log_debug_errno(errno, "Unable to test whether /sys/firmware/acpi/tables/TPM2 exists, assuming it doesn't: %m");
                }
        }

        return cache;
}

#endif

bool efi_loader_entry_name_valid(const char *s) {

        if (!filename_is_valid(s)) /* Make sure entry names fit in filenames */
                return false;

        return in_charset(s, ALPHANUMERICAL "+-_.");
}

char *efi_tilt_backslashes(char *s) {
        char *p;

        for (p = s; *p; p++)
                if (*p == '\\')
                        *p = '/';

        return s;
}
