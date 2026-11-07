/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "addon-media.h"
#include "device-path-util.h"
#include "efi-log.h"
#include "efi-string.h"
#include "proto/device-path.h"
#include "proto/load-file.h"
#include "string-util.h"
#include "util.h"

/* Addons are passed from the boot loader to the stub as LoadFile2 objects, one per addon, each with a
 * VenMedia(ADDON_MEDIA_GUID)/<filename> device path, similar to how the initrd is passed to the kernel. */

typedef struct AddonLoader {
        EFI_LOAD_FILE_PROTOCOL load_file;
        EFI_DEVICE_PATH *device_path;
        struct iovec data;
} AddonLoader;

static EFIAPI EFI_STATUS addon_load_file(
                EFI_LOAD_FILE_PROTOCOL *this,
                EFI_DEVICE_PATH *file_path,
                bool boot_policy,
                size_t *buffer_size,
                void *buffer) {

        if (!this || !buffer_size || !file_path)
                return EFI_INVALID_PARAMETER;
        if (boot_policy)
                return EFI_UNSUPPORTED;

        AddonLoader *loader = (AddonLoader *) this;
        if (!buffer || *buffer_size < loader->data.iov_len) {
                *buffer_size = loader->data.iov_len;
                return EFI_BUFFER_TOO_SMALL;
        }

        memcpy(buffer, loader->data.iov_base, loader->data.iov_len);
        *buffer_size = loader->data.iov_len;
        return EFI_SUCCESS;
}

static EFI_STATUS make_addon_device_path(const char16_t *path, EFI_DEVICE_PATH **ret_dp) {
        assert(path);
        assert(ret_dp);

        size_t path_size = strsize16(path);
        if (path_size > UINT16_MAX - offsetof(FILEPATH_DEVICE_PATH, PathName))
                return EFI_INVALID_PARAMETER;

        VENDOR_DEVICE_PATH *dp = xmalloc(
                        sizeof(VENDOR_DEVICE_PATH) + offsetof(FILEPATH_DEVICE_PATH, PathName) + path_size + sizeof(EFI_DEVICE_PATH));

        *dp = (VENDOR_DEVICE_PATH) {
                .Header = {
                        .Type = MEDIA_DEVICE_PATH,
                        .SubType = MEDIA_VENDOR_DP,
                        .Length = sizeof(VENDOR_DEVICE_PATH),
                },
                .Guid = ADDON_MEDIA_GUID,
        };

        FILEPATH_DEVICE_PATH *file_dp = (FILEPATH_DEVICE_PATH *) device_path_next_node(&dp->Header);
        file_dp->Header = (EFI_DEVICE_PATH) {
                .Type = MEDIA_DEVICE_PATH,
                .SubType = MEDIA_FILEPATH_DP,
                .Length = offsetof(FILEPATH_DEVICE_PATH, PathName) + path_size,
        };
        memcpy(file_dp->PathName, path, path_size);

        *device_path_next_node(&file_dp->Header) = DEVICE_PATH_END_NODE;
        *ret_dp = &dp->Header;
        return EFI_SUCCESS;
}

EFI_STATUS addon_media_register(const char16_t *filename, struct iovec *data, EFI_HANDLE *ret_handle) {
        EFI_STATUS err;

        assert(filename);
        assert(data);
        assert(ret_handle);

        _cleanup_free_ EFI_DEVICE_PATH *dp = NULL;
        err = make_addon_device_path(filename, &dp);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to make addon media device path for %ls: %m", filename);

        _cleanup_free_ AddonLoader *loader = xnew(AddonLoader, 1);
        *loader = (AddonLoader) {
                .load_file.LoadFile = addon_load_file,
                .device_path = dp,
                .data = *data,
        };

        EFI_HANDLE handle = NULL;
        err = BS->InstallMultipleProtocolInterfaces(
                        &handle,
                        MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), loader->device_path,
                        MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), loader,
                        /* sentinel= */ NULL);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to install addon media for %ls: %m", filename);

        TAKE_PTR(dp);
        TAKE_PTR(loader);

        *ret_handle = handle;
        return EFI_SUCCESS;
}

EFI_STATUS addon_media_unregister(EFI_HANDLE handle) {
        AddonLoader *loader;
        EFI_STATUS err;

        if (!handle)
                return EFI_SUCCESS;

        err = BS->HandleProtocol(handle, MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), (void **) &loader);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to acquire LoadFile2 protocol on our own addon handle: %m");

        err = BS->UninstallMultipleProtocolInterfaces(
                        handle,
                        MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), loader->device_path,
                        MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), loader,
                        /* sentinel= */ NULL);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to uninstall addon media: %m");

        iovec_done(&loader->data);
        free(loader->device_path);
        free(loader);
        return EFI_SUCCESS;
}

const char16_t* addon_media_filename(const EFI_DEVICE_PATH *dp) {
        assert(dp);

        /* Returns the addon file name if 'dp' is an addon media device path, NULL otherwise */

        if (dp->Type != MEDIA_DEVICE_PATH ||
            dp->SubType != MEDIA_VENDOR_DP ||
            dp->Length != sizeof(VENDOR_DEVICE_PATH) ||
            memcmp(&((const VENDOR_DEVICE_PATH *) dp)->Guid, MAKE_GUID_PTR(ADDON_MEDIA), sizeof(EFI_GUID)) != 0)
                return NULL;

        const FILEPATH_DEVICE_PATH *file_dp = (const FILEPATH_DEVICE_PATH *) device_path_next_node(dp);
        if (file_dp->Header.Type != MEDIA_DEVICE_PATH ||
            file_dp->Header.SubType != MEDIA_FILEPATH_DP ||
            file_dp->Header.Length < offsetof(FILEPATH_DEVICE_PATH, PathName) ||
            (file_dp->Header.Length - offsetof(FILEPATH_DEVICE_PATH, PathName)) % sizeof(char16_t) != 0)
                return NULL;

        const char16_t *path = (const char16_t *) ((const uint8_t *) file_dp + offsetof(FILEPATH_DEVICE_PATH, PathName));
        size_t n = (file_dp->Header.Length - offsetof(FILEPATH_DEVICE_PATH, PathName)) / sizeof(char16_t);
        if (strnlen16(path, n) >= n)
                return NULL;

        /* Accept paths with and without a leading backslash, and only take the file name part */
        return empty_to_null(path_filename16(path));
}

static int addon_media_compare(const EFI_DEVICE_PATH *a, const EFI_DEVICE_PATH *b) {
        return strcmp16(addon_media_filename(a), addon_media_filename(b));
}

EFI_STATUS addon_media_find(EFI_DEVICE_PATH ***ret_paths, size_t *ret_n_paths) {
        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles = 0;
        EFI_STATUS err;

        assert(ret_paths);
        assert(ret_n_paths);

        err = BS->LocateHandleBuffer(ByProtocol, MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), NULL, &n_handles, &handles);
        if (err == EFI_NOT_FOUND) {
                *ret_paths = NULL;
                *ret_n_paths = 0;
                return EFI_SUCCESS;
        }
        if (err != EFI_SUCCESS)
                return err;

        _cleanup_free_ EFI_DEVICE_PATH **paths = xnew(EFI_DEVICE_PATH *, n_handles);
        size_t n_paths = 0;

        FOREACH_ARRAY(h, handles, n_handles) {
                EFI_DEVICE_PATH *dp;

                err = BS->HandleProtocol(*h, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp);
                if (err != EFI_SUCCESS || !addon_media_filename(dp))
                        continue;

                paths[n_paths++] = dp;
        }

        /* Sort by file name, like the other addons, so that the measurements are predictable */
        sort_pointer_array((void **) paths, n_paths, (compare_pointer_func_t) addon_media_compare);

        /* Drop duplicate file names, the first one wins (the sort is stable) */
        size_t n_unique = 0;
        FOREACH_ARRAY(dp, paths, n_paths) {
                if (n_unique > 0 && addon_media_compare(paths[n_unique - 1], *dp) == 0) {
                        log_debug("Ignoring duplicate addon %ls.", addon_media_filename(*dp));
                        continue;
                }

                paths[n_unique++] = *dp;
        }
        n_paths = n_unique;

        *ret_paths = TAKE_PTR(paths);
        *ret_n_paths = n_paths;
        return EFI_SUCCESS;
}
