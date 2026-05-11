/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-log.h"
#include "hii.h"
#include "proto/hii-database.h"
#include "util.h"

char16_t *hii_query_keyboard_layout_language(void) {
        EFI_HII_DATABASE_PROTOCOL *hii_db = NULL;
        EFI_STATUS err;

        err = BS->LocateProtocol(MAKE_GUID_PTR(EFI_HII_DATABASE_PROTOCOL), /* Registration= */ NULL, (void **) &hii_db);
        if (err != EFI_SUCCESS) {
                log_debug_status(err, "HII database protocol not available, ignoring: %m");
                return NULL;
        }

        /* First call sizes the layout. We pass length=0 / buffer=NULL and expect EFI_BUFFER_TOO_SMALL. */
        uint16_t length = 0;
        err = hii_db->GetKeyboardLayout(hii_db, /* KeyGuid= */ NULL, &length, /* KeyboardLayout= */ NULL);
        if (err != EFI_BUFFER_TOO_SMALL) {
                log_debug_status(err, "Initial GetKeyboardLayout did not report required buffer size, ignoring: %m");
                return NULL;
        }
        if (length < sizeof(EFI_HII_KEYBOARD_LAYOUT)) {
                log_debug("Reported keyboard layout size %u is smaller than the header, ignoring.", length);
                return NULL;
        }

        _cleanup_free_ EFI_HII_KEYBOARD_LAYOUT *layout = xmalloc(length);
        err = hii_db->GetKeyboardLayout(hii_db, /* KeyGuid= */ NULL, &length, layout);
        if (err != EFI_SUCCESS) {
                log_debug_status(err, "Failed to retrieve current keyboard layout, ignoring: %m");
                return NULL;
        }

        if (length < sizeof(EFI_HII_KEYBOARD_LAYOUT)) {
                log_debug("Reported keyboard layout size %u shrank below the header, ignoring.", length);
                return NULL;
        }

        if (layout->LayoutLength != length) {
                log_debug("Keyboard layout reports inconsistent LayoutLength %u vs %u, ignoring.",
                          layout->LayoutLength, length);
                return NULL;
        }

        uint32_t off = layout->LayoutDescriptorStringOffset;
        if (off > length || length - off < sizeof(EFI_DESCRIPTION_STRING_BUNDLE)) {
                log_debug("Keyboard layout descriptor string offset %u out of bounds (length %u), ignoring.",
                          off, length);
                return NULL;
        }

        const EFI_DESCRIPTION_STRING_BUNDLE *bundle = (const EFI_DESCRIPTION_STRING_BUNDLE *) ((const uint8_t *) layout + off);
        if (bundle->DescriptionCount == 0) {
                log_debug("Keyboard layout has no description strings, ignoring.");
                return NULL;
        }

        /* Walk Strings[] looking for the U+0020 that terminates the first language tag. */
        size_t max_chars = (length - off - sizeof(EFI_DESCRIPTION_STRING_BUNDLE)) / sizeof(char16_t);
        size_t n;
        for (n = 0; n < max_chars; n++)
                if (bundle->Strings[n] == u' ')
                        break;
        if (n == max_chars) {
                log_debug("Keyboard layout language tag is not terminated by a space, ignoring.");
                return NULL;
        }
        if (n == 0) {
                log_debug("Keyboard layout language tag is empty, ignoring.");
                return NULL;
        }

        char16_t *s = xnew(char16_t, n + 1);
        memcpy(s, bundle->Strings, n * sizeof(char16_t));
        s[n] = u'\0';
        return s;
}
