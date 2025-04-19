/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "edid.h"
#include "edid-fundamental.h"
#include "log.h"
#include "proto/edid-discovered.h"
#include "util.h"

EFI_STATUS edid_get_discovered_panel_id(char16_t **ret_panel) {
        assert(ret_panel);
        EFI_EDID_DISCOVERED_PROTOCOL *edid_discovered = NULL;
        EFI_STATUS status = BS->LocateProtocol(MAKE_GUID_PTR(EFI_EDID_DISCOVERED_PROTOCOL), NULL, (void **) &edid_discovered);
        if (EFI_STATUS_IS_ERROR(status))
                return status;

        if (!edid_discovered)
                return EFI_UNSUPPORTED;
        if (!edid_discovered->Edid)
                return EFI_UNSUPPORTED;
        if (edid_discovered->SizeOfEdid == 0)
                return EFI_UNSUPPORTED;

        /* EDID size is at least 128 as per the specification */
        if (edid_discovered->SizeOfEdid < 128)
                return EFI_BUFFER_TOO_SMALL;

        EdidHeader header;
        if (!edid_parse_blob(edid_discovered->Edid, edid_discovered->SizeOfEdid, &header))
                return EFI_INCOMPATIBLE_VERSION;

        *ret_panel = xnew0(char16_t, 8);
        if (!edid_get_panel_id(&header, *ret_panel))
                return EFI_INVALID_PARAMETER;

        return EFI_SUCCESS;
}
