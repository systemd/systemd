/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-log.h"
#include "initrd.h"
#include "iovec-util-fundamental.h"
#include "proto/device-path.h"
#include "proto/load-file.h"
#include "util.h"

#define LINUX_INITRD_MEDIA_GUID \
        GUID_DEF(0x5568e427, 0x68fc, 0x4f3d, 0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68)

/* extend LoadFileProtocol */
struct initrd_loader {
        EFI_LOAD_FILE_PROTOCOL load_file;
        struct iovec data;
};

/* static structure for LINUX_INITRD_MEDIA device path
   see https://github.com/torvalds/linux/blob/v5.13/drivers/firmware/efi/libstub/efi-stub-helper.c
 */
static const struct {
        VENDOR_DEVICE_PATH vendor;
        EFI_DEVICE_PATH end;
} _packed_ efi_initrd_device_path = {
        .vendor = {
                .Header = {
                        .Type = MEDIA_DEVICE_PATH,
                        .SubType = MEDIA_VENDOR_DP,
                        .Length = sizeof(efi_initrd_device_path.vendor),
                },
                .Guid = LINUX_INITRD_MEDIA_GUID
        },
        .end = {
                .Type = END_DEVICE_PATH_TYPE,
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                .Length = sizeof(efi_initrd_device_path.end),
        }
};

static EFIAPI EFI_STATUS initrd_load_file(
                EFI_LOAD_FILE_PROTOCOL *this,
                EFI_DEVICE_PATH *file_path,
                bool boot_policy,
                size_t *buffer_size,
                void *buffer) {

        struct initrd_loader *loader;

        if (!this || !buffer_size || !file_path)
                return EFI_INVALID_PARAMETER;
        if (boot_policy)
                return EFI_UNSUPPORTED;

        loader = (struct initrd_loader *) this;
        if (!iovec_is_set(&loader->data))
                return EFI_NOT_FOUND;

        if (!buffer || *buffer_size < loader->data.iov_len) {
                *buffer_size = loader->data.iov_len;
                return EFI_BUFFER_TOO_SMALL;
        }

        memcpy(buffer, loader->data.iov_base, loader->data.iov_len);
        *buffer_size = loader->data.iov_len;
        return EFI_SUCCESS;
}

EFI_STATUS initrd_register(
                const struct iovec *initrd,
                EFI_HANDLE *ret_initrd_handle) {

        EFI_STATUS err;

        assert(ret_initrd_handle);

        /* If no initrd is specified we'll not install any. This avoids registration of the protocol for that
         * case, leaving it open for something else. */

        if (!iovec_is_set(initrd))
                return EFI_SUCCESS;

        /* We want to override the LINUX_INITRD_MEDIA device, let's hence first unregister any existing
         * one. We don't really expect multiple of these to be registered, but who knows? Let's kill all we
         * can find. */
        for (;;) {
                EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *) &efi_initrd_device_path;
                EFI_HANDLE handle = NULL;
                err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), &dp, &handle);
                if (err == EFI_NOT_FOUND) /* Yay! All gone */
                        break;
                if (err != EFI_SUCCESS)
                        return log_debug_status(err, "Failed to locate LINUX_INITRD_MEDIA device: %m");

                /* Get actually installed pointer for the device path */
                err = BS->HandleProtocol(handle, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void**) &dp);
                if (err != EFI_SUCCESS)
                        return log_debug_status(err, "Failed to acquire DevicePath protocol on LINUX_INITRD_MEDIA device: %m");

                /* Take away the device path protocol */
                err = BS->UninstallMultipleProtocolInterfaces(
                                handle,
                                MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), dp,
                                /* sentinel= */ NULL);
                if (err != EFI_SUCCESS)
                        return log_debug_status(err, "Unable to release DevicePath protocol from old handle: %m");

                /* NB: we leave the handle around, (and thus leave the LoadFile2 protocol installed) because
                 * the owner might be unhappy if we destroy it for them. It will no longer have the device
                 * path we want to take possession of on it though. The assumption here is that whoever
                 * registered the device path is OK with the device path being taken away, even if it might
                 * not be OK with the handle being invalidated as a whole. */

                log_debug("Successfully unregistered previous LINUX_INITRD_MEDIA device.");
        }

        _cleanup_free_ struct initrd_loader *loader = xnew(struct initrd_loader, 1);
        *loader = (struct initrd_loader) {
                .load_file.LoadFile = initrd_load_file,
                .data = *initrd,
        };

        /* create a new handle and register the LoadFile2 protocol with the InitrdMediaPath on it */
        err = BS->InstallMultipleProtocolInterfaces(
                        ret_initrd_handle,
                        MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), &efi_initrd_device_path,
                        MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), loader,
                        /* sentinel= */ NULL);
        if (err != EFI_SUCCESS)
                return log_debug_status(err, "Failed to install new initrd device: %m");

        log_debug("Installed new initrd of size %zu.", loader->data.iov_len);

        TAKE_PTR(loader);
        return EFI_SUCCESS;
}

EFI_STATUS initrd_unregister(EFI_HANDLE initrd_handle) {
        EFI_STATUS err;
        struct initrd_loader *loader;

        if (!initrd_handle)
                return EFI_SUCCESS;

        /* get the LoadFile2 protocol that we allocated earlier */
        err = BS->HandleProtocol(initrd_handle, MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), (void **) &loader);
        if (err != EFI_SUCCESS)
                return err;

        /* We uninstall the DevicePath and the LoadFile2 protocol in separate steps. That's because we want
         * to gracefully handle the former (because it's OK if something else takes over the device path),
         * but be strict on the latter, because that's genuinely ours */

        (void) BS->UninstallMultipleProtocolInterfaces(
                        initrd_handle,
                        MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), &efi_initrd_device_path,
                        NULL);

        /* This second call will also invalidate the handle, because it should be the last protocol on the handle */
        err = BS->UninstallMultipleProtocolInterfaces(
                        initrd_handle,
                        MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), loader,
                        NULL);
        if (err != EFI_SUCCESS)
                return err;

        initrd_handle = NULL;
        free(loader);
        return EFI_SUCCESS;
}

EFI_STATUS initrd_read_previous(struct iovec *ret_initrd) {
        EFI_STATUS err;

        /* If there's already an initrd registered, read it out, so that we can incorporate it in ours */

        assert(ret_initrd);

        /* Get from the device path to the handle */
        EFI_DEVICE_PATH *dp = (EFI_DEVICE_PATH *) &efi_initrd_device_path;
        EFI_HANDLE handle;
        err = BS->LocateDevicePath(MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), &dp, &handle);
        if (err != EFI_SUCCESS)
                return err;

        /* Get from the handle to the protocol */
        EFI_LOAD_FILE2_PROTOCOL *protocol = NULL;
        err = BS->HandleProtocol(handle, MAKE_GUID_PTR(EFI_LOAD_FILE2_PROTOCOL), (void**) &protocol);
        if (err != EFI_SUCCESS)
                return err;

        size_t size = 0;
        err = protocol->LoadFile(protocol, dp, /* bootPolicy= */ false, &size, /* Buffer= */ NULL);
        if (err != EFI_BUFFER_TOO_SMALL)
                return err;
        if (size == 0)
                return EFI_NOT_FOUND; /* Treat empty initrds like missing ones */

        _cleanup_free_ void *data = xmalloc(size);
        err = protocol->LoadFile(protocol, dp, /* bootPolicy= */ false, &size, data);
        if (err != EFI_SUCCESS)
                return err;

        *ret_initrd = (struct iovec) {
                .iov_base = TAKE_PTR(data),
                .iov_len = size,
        };

        return EFI_SUCCESS;
}
