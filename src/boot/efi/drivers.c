/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "drivers.h"
#include "util.h"

static EFI_STATUS load_one_driver(
                EFI_HANDLE parent_image,
                EFI_LOADED_IMAGE *loaded_image,
                const CHAR16 *fname) {

        _cleanup_(unload_imagep) EFI_HANDLE image = NULL;
        _cleanup_freepool_ EFI_DEVICE_PATH *path = NULL;
        _cleanup_freepool_ CHAR16 *spath = NULL;
        EFI_STATUS err;

        assert(parent_image);
        assert(loaded_image);
        assert(fname);

        spath = xasprintf("\\EFI\\systemd\\drivers\\%ls", fname);
        err = make_file_device_path(loaded_image->DeviceHandle, spath, &path);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error making file device path: %m");

        err = BS->LoadImage(FALSE, parent_image, path, NULL, 0, &image);
        if (EFI_ERROR(err))
                return log_error_status(err, "Failed to load image %ls: %m", fname);

        err = BS->HandleProtocol(image, &LoadedImageProtocol, (void **)&loaded_image);
        if (EFI_ERROR(err))
                return log_error_status(err, "Failed to find protocol in driver image %ls: %m", fname);

        if (loaded_image->ImageCodeType != EfiBootServicesCode &&
            loaded_image->ImageCodeType != EfiRuntimeServicesCode)
                return log_error("Image %ls is not a driver, refusing.", fname);

        err = BS->StartImage(image, NULL, NULL);
        if (EFI_ERROR(err)) {
                /* EFI_ABORTED signals an initializing driver. It uses this error code on success
                 * so that it is unloaded after. */
                if (err != EFI_ABORTED)
                        log_error_status(err, "Failed to start image %ls: %m", fname);
                return err;
        }

        TAKE_PTR(image);
        return EFI_SUCCESS;
}

static EFI_STATUS reconnect(void) {
          _cleanup_freepool_ EFI_HANDLE *handles = NULL;
          UINTN n_handles = 0;
          EFI_STATUS err;

          /* Reconnects all handles, so that any loaded drivers can take effect. */

          err = BS->LocateHandleBuffer(AllHandles, NULL, NULL, &n_handles, &handles);
          if (EFI_ERROR(err))
                  return log_error_status(err, "Failed to get list of handles: %m");

          for (UINTN i = 0; i < n_handles; i++) {
                  err = BS->ConnectController(handles[i], NULL, NULL, TRUE);
                  if (err == EFI_NOT_FOUND) /* No drivers for this handle */
                          continue;
                  if (EFI_ERROR(err))
                          log_error_status(err, "Failed to reconnect handle %zu, ignoring: %m", i);
          }

          return EFI_SUCCESS;
}

EFI_STATUS load_drivers(
                EFI_HANDLE parent_image,
                EFI_LOADED_IMAGE *loaded_image,
                EFI_FILE *root_dir) {

        _cleanup_(file_closep) EFI_FILE *drivers_dir = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *dirent = NULL;
        UINTN dirent_size = 0, n_succeeded = 0;
        EFI_STATUS err;

        err = open_directory(
                        root_dir,
                        L"\\EFI\\systemd\\drivers",
                        &drivers_dir);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
        if (EFI_ERROR(err))
                return log_error_status(err, "Failed to open \\EFI\\systemd\\drivers: %m");

        for (;;) {
                err = readdir_harder(drivers_dir, &dirent, &dirent_size);
                if (EFI_ERROR(err))
                        return log_error_status(err, "Failed to read extra directory of loaded image: %m");
                if (!dirent) /* End of directory */
                        break;

                if (dirent->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(dirent->Attribute, EFI_FILE_DIRECTORY))
                        continue;
                if (!endswith_no_case(dirent->FileName, EFI_MACHINE_TYPE_NAME L".efi"))
                        continue;

                err = load_one_driver(parent_image, loaded_image, dirent->FileName);
                if (EFI_ERROR(err))
                        continue;

                n_succeeded++;
        }

        if (n_succeeded > 0)
                (void) reconnect();

        return EFI_SUCCESS;
}
