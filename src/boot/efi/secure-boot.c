#include "secure-boot.h"
#include "util.h"

BOOLEAN secure_boot_enabled(void) {
        _cleanup_freepool_ CHAR8 *b = NULL;
        UINTN size;

        if (efivar_get_raw(GLOBAL_GUID, L"SecureBoot", &b, &size) == EFI_SUCCESS)
                return *b > 0;

        return FALSE;
}
