/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "addon-util.h"
#include "proto/device-path.h"
#include "util.h"
#include "log.h"

EFI_STATUS addons_install_proto(EFI_LOADED_IMAGE_PROTOCOL *stub_image, char16_t * const *addons) {
        EFI_STATUS err;
        EFI_DEVICE_PATH **dps;

        assert(stub_image);

        err = make_multiple_file_device_path(stub_image->DeviceHandle, addons, &dps);
        if (err != EFI_SUCCESS || dps == NULL)
                return err;

        return BS->InstallMultipleProtocolInterfaces(&stub_image->DeviceHandle,
                                            MAKE_GUID_PTR(SYSTEMD_ADDON_MEDIA),
                                            dps, NULL);
}

EFI_STATUS addons_unload_proto(EFI_HANDLE *addons)
{
        EFI_STATUS err;
        EFI_DEVICE_PATH *dps;

        assert(addons);

        if (!*addons)
                return EFI_SUCCESS;

        /* get the EFI_DEVICE_PATH* interface that we allocated earlier */
        err = BS->HandleProtocol(*addons, MAKE_GUID_PTR(SYSTEMD_ADDON_MEDIA),
                        (void **) &dps);
        if (err != EFI_SUCCESS)
                return err;

        err = BS->UninstallMultipleProtocolInterfaces(*addons,
                        MAKE_GUID_PTR(SYSTEMD_ADDON_MEDIA),
                        &dps, NULL);

        if (err != EFI_SUCCESS)
                return err;

        *addons = NULL;
        return EFI_SUCCESS;
}
