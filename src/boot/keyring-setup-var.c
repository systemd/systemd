/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"
#include "keyring-setup-var.h"
#include "util.h"

bool keyring_setup_credential_name_is_valid(const char *name) {
        const char *e;

        assert(name);

        /* The names become file names in the initrd generated from the payload, hence be strict. (The
         * consumer's own validation of the name suffix is stricter still.) */

        e = startswith8(name, KEYRING_SETUP_NAME_PREFIX);
        if (!e || *e == 0)
                return false;

        if (strlen8(name) > 250) /* a ".cred" suffix is appended, and the result must fit in NAME_MAX (255) */
                return false;

        for (const char *c = name; *c != 0; c++)
                if (!((*c >= 'a' && *c <= 'z') ||
                      (*c >= '0' && *c <= '9') ||
                      IN_SET(*c, '.', '_', '-')))
                        return false;

        return true;
}

EFI_STATUS keyring_setup_next_record(
                const void *data,
                size_t size,
                size_t *offset,
                const char **ret_name,
                const void **ret_payload,
                size_t *ret_payload_size) {

        size_t o, name_len, payload_size;
        const uint8_t *p;
        const char *name;

        assert(data || size == 0);
        assert(offset);
        assert(ret_name);
        assert(ret_payload);
        assert(ret_payload_size);

        /* Parses one record of a LoaderKeyringSetup payload: a NUL terminated credential name, a 32-bit
         * little endian length field, and that many bytes of certificate data. Returns EFI_NOT_FOUND when
         * the end of the payload is reached cleanly, EFI_INVALID_PARAMETER if it is malformed. */

        o = *offset;
        if (o >= size)
                return EFI_NOT_FOUND;

        name = (const char *) data + o;
        name_len = strnlen8(name, size - o);
        if (name_len >= size - o ||                        /* no NUL before the end? */
            size - o - name_len - 1 < sizeof(uint32_t))    /* no space for the length field? */
                return EFI_INVALID_PARAMETER;
        o += name_len + 1;

        /* Read the length field byte-wise, both for alignment and for endianness */
        p = (const uint8_t *) data + o;
        payload_size = (size_t) p[0] | ((size_t) p[1] << 8) | ((size_t) p[2] << 16) | ((size_t) p[3] << 24);
        o += sizeof(uint32_t);

        if (payload_size == 0 || payload_size > size - o)
                return EFI_INVALID_PARAMETER;

        if (!keyring_setup_credential_name_is_valid(name))
                return EFI_INVALID_PARAMETER;

        *ret_name = name;
        *ret_payload = (const uint8_t *) data + o;
        *ret_payload_size = payload_size;
        *offset = o + payload_size;
        return EFI_SUCCESS;
}
