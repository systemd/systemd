/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;

char** taint_strv(const Manager *m);
char* taint_string(const Manager *m);
