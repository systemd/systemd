/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* 256 bit keys = 32 bytes */
#define RECOVERY_KEY_MODHEX_RAW_LENGTH 32

/* Formatted as sequences of 64 modhex characters, with dashes inserted after multiples of 8 chars (incl. trailing NUL) */
#define RECOVERY_KEY_MODHEX_FORMATTED_LENGTH (RECOVERY_KEY_MODHEX_RAW_LENGTH*2/8*9)

int make_recovery_key(char **ret);

extern const char modhex_alphabet[16];

int decode_modhex_char(char x);

int normalize_recovery_key(const char *password, char **ret);
