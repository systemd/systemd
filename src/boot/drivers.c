/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "drivers.h"
#include "efi-log.h"
#include "string-util-fundamental.h"
#include "util.h"

static EFI_STATUS load_one_driver(
                EFI_HANDLE parent_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *fname) {

        _cleanup_(unload_imagep) EFI_HANDLE image = NULL;
        _cleanup_free_ EFI_DEVICE_PATH *path = NULL;
        _cleanup_free_ char16_t *spath = NULL;
        EFI_STATUS err;

        assert(parent_image);
        assert(loaded_image);
        assert(fname);

        spath = xasprintf("\\EFI\\systemd\\drivers\\%ls", fname);
        err = make_file_device_path(loaded_image->DeviceHandle, spath, &path);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error making file device path: %m");

        err = BS->LoadImage(false, parent_image, path, NULL, 0, &image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to load image %ls: %m", fname);

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to find protocol in driver image %ls: %m", fname);

        if (loaded_image->ImageCodeType != EfiBootServicesCode &&
            loaded_image->ImageCodeType != EfiRuntimeServicesCode)
                return log_error("Image %ls is not a driver, refusing.", fname);

        err = BS->StartImage(image, NULL, NULL);
        if (err != EFI_SUCCESS) {
                /* EFI_ABORTED signals an initializing driver. It uses this error code on success
                 * so that it is unloaded after. */
                if (err != EFI_ABORTED)
                        log_error_status(err, "Failed to start image %ls: %m", fname);
                return err;
        }

        TAKE_PTR(image);
        return EFI_SUCCESS;
}

EFI_STATUS reconnect_all_drivers(void) {
        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles = 0;
        EFI_STATUS err;

        /* Reconnects all handles, so that any loaded drivers can take effect. */

        err = BS->LocateHandleBuffer(
                        AllHandles,
                        /* Protocol= */ NULL,
                        /* SearchKey= */ NULL,
                        &n_handles, &handles);
        if (!IN_SET(err, EFI_SUCCESS, EFI_NOT_FOUND))
                return log_error_status(err, "Failed to get list of handles: %m");

        FOREACH_ARRAY(h, handles, n_handles)
                /* Some firmware gives us some bogus handles (or they might become bad due to
                 * reconnecting everything). Security policy may also prevent us from doing so too.
                 * There is nothing we can realistically do on errors anyways, so just ignore them. */
                (void) BS->ConnectController(
                                *h,
                                /* DriverImageHandle= */ NULL,
                                /* RemainingDevicePath= */ NULL,
                                /* Recursive= */ true);

        return EFI_SUCCESS;
}

EFI_STATUS load_drivers(
                EFI_HANDLE parent_image,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                EFI_FILE *root_dir) {

        _cleanup_file_close_ EFI_FILE *drivers_dir = NULL;
        _cleanup_free_ EFI_FILE_INFO *dirent = NULL;
        size_t dirent_size = 0, n_succeeded = 0;
        EFI_STATUS err;

        err = open_directory(
                        root_dir,
                        u"\\EFI\\systemd\\drivers",
                        &drivers_dir);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to open \\EFI\\systemd\\drivers: %m");

        for (;;) {
                err = readdir(drivers_dir, &dirent, &dirent_size);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to read extra directory of loaded image: %m");
                if (!dirent) /* End of directory */
                        break;

                if (dirent->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(dirent->Attribute, EFI_FILE_DIRECTORY))
                        continue;
                if (!endswith_no_case(dirent->FileName, EFI_MACHINE_TYPE_NAME u".efi"))
                        continue;

                err = load_one_driver(parent_image, loaded_image, dirent->FileName);
                if (err != EFI_SUCCESS)
                        continue;

                n_succeeded++;
        }

        if (n_succeeded > 0)
                (void) reconnect_all_drivers();

        return EFI_SUCCESS;
}
