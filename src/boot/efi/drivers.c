/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>

#include "drivers.h"
#include "util.h"

static VOID efi_unload_image(EFI_HANDLE *h) {
        if (*h)
                (VOID) uefi_call_wrapper(BS->UnloadImage, 1, *h);
}

static EFI_STATUS load_one_driver(
                EFI_HANDLE parent_image,
                EFI_LOADED_IMAGE *loaded_image,
                const CHAR16 *fname) {

        _cleanup_(efi_unload_image) EFI_HANDLE image = NULL;
        _cleanup_freepool_ EFI_DEVICE_PATH *path = NULL;
        _cleanup_freepool_ CHAR16 *spath = NULL;
        EFI_STATUS err;

        assert(parent_image);
        assert(loaded_image);
        assert(fname);

        spath = PoolPrint(L"\\EFI\\systemd\\drivers\\%s", fname);
        if (!spath)
                return log_oom();

        path = FileDevicePath(loaded_image->DeviceHandle, spath);
        if (!path)
                return log_oom();

        err = uefi_call_wrapper(
                        BS->LoadImage, 6,
                        FALSE,
                        parent_image,
                        path,
                        NULL, 0,
                        &image);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Failed to load image %s: %r", fname, err);

        err = uefi_call_wrapper(
                        BS->HandleProtocol, 3,
                        image,
                        &LoadedImageProtocol,
                        (VOID **)&loaded_image);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Failed to find protocol in driver image s: %r", fname, err);

        if (loaded_image->ImageCodeType != EfiBootServicesCode &&
            loaded_image->ImageCodeType != EfiRuntimeServicesCode)
                return log_error_status_stall(EFI_INVALID_PARAMETER, L"Image %s is not a driver, refusing: %r", fname);

        err = uefi_call_wrapper(
                        BS->StartImage, 3,
                        image,
                        NULL,
                        NULL);
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Failed to start image %s: %r", fname, err);

        TAKE_PTR(image);
        return EFI_SUCCESS;
}

static EFI_STATUS reconnect(VOID) {
          _cleanup_freepool_ EFI_HANDLE *handles = NULL;
          UINTN n_handles = 0;
          EFI_STATUS err;

          /* Reconnects all handles, so that any loaded drivers can take effect. */

          err = uefi_call_wrapper(
                          BS->LocateHandleBuffer, 5,
                          AllHandles,
                          NULL,
                          NULL,
                          &n_handles,
                          &handles);
          if (EFI_ERROR(err))
                  return log_error_status_stall(err, L"Failed to get list of handles: %r", err);

          for (UINTN i = 0; i < n_handles; i++) {
                  err = uefi_call_wrapper(
                                  BS->ConnectController, 4,
                                  handles[i],
                                  NULL,
                                  NULL,
                                  TRUE);
                  if (err == EFI_NOT_FOUND) /* No drivers for this handle */
                          continue;
                  if (EFI_ERROR(err))
                          log_error_status_stall(err, L"Failed to reconnect handle %u, ignoring: %r", i, err);
          }

          return EFI_SUCCESS;
}

EFI_STATUS load_drivers(
                EFI_HANDLE parent_image,
                EFI_LOADED_IMAGE *loaded_image,
                EFI_FILE_HANDLE root_dir) {

        _cleanup_(FileHandleClosep) EFI_FILE_HANDLE drivers_dir = NULL;
        _cleanup_freepool_ EFI_FILE_INFO *dirent = NULL;
        _cleanup_freepool_ EFI_DEVICE_PATH *path = NULL;
        UINTN dirent_size = 0, n_succeeded = 0;
        EFI_STATUS err;

        err = open_directory(
                        root_dir,
                        L"\\EFI\\systemd\\drivers",
                        &drivers_dir);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
        if (EFI_ERROR(err))
                return log_error_status_stall(err, L"Failed to open \\EFI\\systemd\\drivers: %r", err);

        for (;;) {
                _cleanup_freepool_ CHAR16 *d = NULL;

                err = readdir_harder(drivers_dir, &dirent, &dirent_size);
                if (EFI_ERROR(err))
                        return log_error_status_stall(err, L"Failed to read extra directory of loaded image: %r", err);
                if (!dirent) /* End of directory */
                        break;

                if (dirent->FileName[0] == '.')
                        continue;
                if (dirent->Attribute & EFI_FILE_DIRECTORY)
                        continue;
                if (!endswith_no_case(dirent->FileName, EFI_MACHINE_TYPE_NAME L".efi"))
                        continue;

                err = load_one_driver(parent_image, loaded_image, dirent->FileName);
                if (EFI_ERROR(err))
                        continue;

                n_succeeded++;
        }

        if (n_succeeded > 0)
                (VOID) reconnect();

        return EFI_SUCCESS;
}
