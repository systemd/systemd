#include "addon-util.h"
#include "proto/device-path.h"
#include "util.h"
#include "log.h"

EFI_STATUS addons_install(EFI_LOADED_IMAGE_PROTOCOL *stub_image, const char16_t **addons)
{
        EFI_STATUS err;
        EFI_DEVICE_PATH *dp;

        STRV_FOREACH(addon, addons)
                log_internal(EFI_SUCCESS, "installing addon %ls", *addon);

        err = make_multiple_file_device_path(stub_image->DeviceHandle, addons, &dp);
        if (err != EFI_SUCCESS)
                return err;

        return BS->InstallMultipleProtocolInterfaces(&stub_image->DeviceHandle,
                                            MAKE_GUID_PTR(SYSTEMD_ADDON_MEDIA),
                                            dp, NULL);
}

EFI_STATUS walk_addons_in_device_path(EFI_DEVICE_PATH *addons, char16_t **files)
{
        return EFI_SUCCESS;
}
