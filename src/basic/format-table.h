/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include "macro.h"

typedef enum TableDataType {
        TABLE_EMPTY,
        TABLE_STRING,
        TABLE_BOOLEAN,
        TABLE_TIMESTAMP,
        TABLE_TIMESPAN,
        TABLE_SIZE,
        TABLE_UINT32,
        _TABLE_DATA_TYPE_MAX,
        _TABLE_DATA_TYPE_INVALID = -1,
} TableDataType;

typedef struct Table Table;
typedef struct TableCell TableCell;

Table *table_new_internal(const char *first_header, ...) _sentinel_;
#define table_new(...) table_new_internal(__VA_ARGS__, NULL)
Table *table_new_raw(size_t n_columns);
Table *table_unref(Table *t);

DEFINE_TRIVIAL_CLEANUP_FUNC(Table*, table_unref);

int table_add_cell_full(Table *t, TableCell **ret_cell, TableDataType type, const void *data, size_t minimum_width, size_t maximum_width, unsigned weight, unsigned align_percent, unsigned ellipsize_percent);
static inline int table_add_cell(Table *t, TableCell **ret_cell, TableDataType type, const void *data) {
        return table_add_cell_full(t, ret_cell, type, data, (size_t) -1, (size_t) -1, (unsigned) -1, (unsigned) -1, (unsigned) -1);
}

int table_dup_cell(Table *t, TableCell *cell);

int table_set_minimum_width(Table *t, TableCell *cell, size_t minimum_width);
int table_set_maximum_width(Table *t, TableCell *cell, size_t maximum_width);
int table_set_weight(Table *t, TableCell *cell, unsigned weight);
int table_set_align_percent(Table *t, TableCell *cell, unsigned percent);
int table_set_ellipsize_percent(Table *t, TableCell *cell, unsigned percent);
int table_set_color(Table *t, TableCell *cell, const char *color);

int table_add_many_internal(Table *t, TableDataType first_type, ...);
#define table_add_many(t, ...) table_add_many_internal(t, __VA_ARGS__, _TABLE_DATA_TYPE_MAX)

void table_set_header(Table *table, bool b);
void table_set_width(Table *t, size_t width);
int table_set_display(Table *t, size_t first_column, ...);
int table_set_sort(Table *t, size_t first_column, ...);

int table_print(Table *t, FILE *f);
int table_format(Table *t, char **ret);

static inline TableCell* TABLE_HEADER_CELL(size_t i) {
        return SIZE_TO_PTR(i + 1);
}

size_t table_get_rows(Table *t);
size_t table_get_columns(Table *t);
