/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Vinay Kulkarni <kulkarniv@vmware.com>
***/

typedef struct Manager Manager;

int manager_parse_config_file(Manager *m);

const struct ConfigPerfItem* networkd_gperf_lookup(const char *key, GPERF_LEN_TYPE length);

int config_parse_duid_type(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata);
int config_parse_duid_rawdata(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata);
