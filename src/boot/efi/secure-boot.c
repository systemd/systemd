#include "secure-boot.h"
#include "util.h"

static const EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

BOOLEAN secure_boot_enabled(void) {
        _cleanup_freepool_ CHAR8 *b = NULL;
        UINTN size;

        if (efivar_get_raw(&global_guid, L"SecureBoot", &b, &size) == EFI_SUCCESS)
                return *b > 0;

        return FALSE;
}
