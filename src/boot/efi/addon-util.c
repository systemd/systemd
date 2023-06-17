#include "addon-util.h"
#include "proto/device-path.h"
#include "util.h"

static const struct {
        VENDOR_DEVICE_PATH vendor;
        EFI_DEVICE_PATH end;
} _packed_ efi_addon_device_path = {
        .vendor = {
                .Header = {
                        .Type = MEDIA_DEVICE_PATH,
                        .SubType = MEDIA_VENDOR_DP,
                        .Length = sizeof(efi_addon_device_path.vendor),
                },
                .Guid = SYSTEMD_ADDON_MEDIA_GUID
        },
        .end = {
                .Type = END_DEVICE_PATH_TYPE,
                .SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
                .Length = sizeof(efi_addon_device_path.end),
        }
};

EFI_STATUS addons_install(EFI_HANDLE device, const char16_t **addons, EFI_HANDLE *ret_addons_handle)
{
        EFI_STATUS err;
        EFI_DEVICE_PATH *addons_dp = (EFI_DEVICE_PATH *) &efi_addon_device_path;

        err = make_multiple_file_device_path(device, addons, &addons_dp);
        if (err != EFI_SUCCESS)
                return err;

        return BS->InstallMultipleProtocolInterfaces(ret_addons_handle,
                                            MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL),
                                            &addons_dp);
}
