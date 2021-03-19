/*
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

const char *cryptsetup_token_version(void);

int cryptsetup_token_open(struct crypt_device *cd, int token,
        char **password, size_t *password_len, void *usrptr);

void cryptsetup_token_dump(struct crypt_device *cd, const char *json);

int cryptsetup_token_validate(struct crypt_device *cd, const char *json);

void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len);
