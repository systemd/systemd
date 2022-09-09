/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>
#include <stdbool.h>

#include "drivers.h"
#include "efi-string.h"
#include "string-util-fundamental.h"
#include "util.h"

#define QEMU_KERNEL_LOADER_FS_MEDIA_GUID                                \
        { 0x1428f772, 0xb64a, 0x441e, {0xb8, 0xc3, 0x9e, 0xbd, 0xd7, 0xf8, 0x93, 0xc7 }}

#define VMM_BOOT_ORDER_GUID \
        { 0x668f4529, 0x63d0, 0x4bb5, {0xb6, 0x5d, 0x6f, 0xbb, 0x9d, 0x36, 0xa4, 0x4a }}

/* detect direct boot */
bool is_direct_boot(EFI_HANDLE device) {
        EFI_STATUS err;
        VENDOR_DEVICE_PATH *dp;

        err = BS->HandleProtocol(device, &DevicePathProtocol, (void **) &dp);
        if (err != EFI_SUCCESS)
                return false;

        /* 'qemu -kernel systemd-bootx64.efi' */
        if (dp->Header.Type == MEDIA_DEVICE_PATH &&
            dp->Header.SubType == MEDIA_VENDOR_DP &&
            memcmp(&dp->Guid, &(EFI_GUID)QEMU_KERNEL_LOADER_FS_MEDIA_GUID, sizeof(EFI_GUID)) == 0)
                return true;

        /* loaded from firmware volume (sd-boot added to ovmf) */
        if (dp->Header.Type == MEDIA_DEVICE_PATH &&
            dp->Header.SubType == MEDIA_PIWG_FW_VOL_DP)
                return true;

        return false;
}

static bool device_path_startswith(const EFI_DEVICE_PATH *dp, const EFI_DEVICE_PATH *start) {
        if (!start)
                return true;
        if (!dp)
                return false;
        for (;;) {
                if (IsDevicePathEnd(start))
                        return true;
                if (IsDevicePathEnd(dp))
                        return false;
                size_t l1 = DevicePathNodeLength(start);
                size_t l2 = DevicePathNodeLength(dp);
                if (l1 != l2)
                        return false;
                if (memcmp(dp, start, l1) != 0)
                        return false;
                start = NextDevicePathNode(start);
                dp    = NextDevicePathNode(dp);
        }
}

/*
 * Try find ESP when not loaded from ESP
 *
 * Inspect all filesystems known to the firmware, try find the ESP.  In case VMMBootOrderNNNN variables are
 * present they are used to inspect the filesystems in the specified order.  When nothing was found or the
 * variables are not present the function will do one final search pass over all filesystems.
 *
 * Recent OVMF builds store the qemu boot order (as specified using the bootindex property on the qemu
 * command line) in VMMBootOrderNNNN.  The variables contain a device path.
 *
 * Example qemu command line:
 *     qemu -virtio-scsi-pci,addr=14.0 -device scsi-cd,scsi-id=4,bootindex=1
 *
 * Resulting variable:
 *     VMMBootOrder0000 = PciRoot(0x0)/Pci(0x14,0x0)/Scsi(0x4,0x0)
 */
EFI_STATUS qemu_open(EFI_HANDLE *ret_qemu_dev, EFI_FILE **ret_qemu_dir) {
        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles;
        EFI_STATUS err, dp_err;

        assert(ret_qemu_dev);
        assert(ret_qemu_dir);

        /* find all file system handles */
        err = BS->LocateHandleBuffer(ByProtocol, &FileSystemProtocol, NULL, &n_handles, &handles);
        if (err != EFI_SUCCESS)
                return err;

        for (size_t order = 0;; order++) {
                _cleanup_free_ EFI_DEVICE_PATH *dp = NULL;
                char16_t order_str[STRLEN("VMMBootOrder") + 4 + 1];

                SPrint(order_str, sizeof(order_str), u"VMMBootOrder%04x", order);
                dp_err = efivar_get_raw(&(EFI_GUID)VMM_BOOT_ORDER_GUID, order_str, (char**)&dp, NULL);

                for (size_t i = 0; i < n_handles; i++) {
                        _cleanup_(file_closep) EFI_FILE *root_dir = NULL, *efi_dir = NULL;
                        EFI_DEVICE_PATH *fs;

                        err = BS->HandleProtocol(handles[i], &DevicePathProtocol, (void **) &fs);
                        if (err != EFI_SUCCESS)
                                return err;

                        /* check against VMMBootOrderNNNN (if set) */
                        if (dp_err == EFI_SUCCESS && !device_path_startswith(fs, dp))
                                continue;

                        err = open_volume(handles[i], &root_dir);
                        if (err != EFI_SUCCESS)
                                continue;

                        /* simple ESP check */
                        err = root_dir->Open(root_dir, &efi_dir, (char16_t*) u"\\EFI",
                                             EFI_FILE_MODE_READ,
                                             EFI_FILE_READ_ONLY | EFI_FILE_DIRECTORY);
                        if (err != EFI_SUCCESS)
                                continue;

                        *ret_qemu_dev = handles[i];
                        *ret_qemu_dir = TAKE_PTR(root_dir);
                        return EFI_SUCCESS;
                }

                if (dp_err != EFI_SUCCESS)
                        EFI_NOT_FOUND;
        }
        assert_not_reached();
}
