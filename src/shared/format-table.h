/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include "json.h"
#include "macro.h"

typedef enum TableDataType {
        TABLE_EMPTY,
        TABLE_STRING,
        TABLE_BOOLEAN,
        TABLE_TIMESTAMP,
        TABLE_TIMESTAMP_UTC,
        TABLE_TIMESTAMP_RELATIVE,
        TABLE_TIMESPAN,
        TABLE_TIMESPAN_MSEC,
        TABLE_SIZE,
        TABLE_BPS,
        TABLE_INT,
        TABLE_INT8,
        TABLE_INT16,
        TABLE_INT32,
        TABLE_INT64,
        TABLE_UINT,
        TABLE_UINT8,
        TABLE_UINT16,
        TABLE_UINT32,
        TABLE_UINT64,
        TABLE_PERCENT,
        TABLE_IFINDEX,
        TABLE_IN_ADDR,  /* Takes a union in_addr_union (or a struct in_addr) */
        TABLE_IN6_ADDR, /* Takes a union in_addr_union (or a struct in6_addr) */
        _TABLE_DATA_TYPE_MAX,

        /* The following are not really data types, but commands for table_add_cell_many() to make changes to
         * a cell just added. */
        TABLE_SET_MINIMUM_WIDTH,
        TABLE_SET_MAXIMUM_WIDTH,
        TABLE_SET_WEIGHT,
        TABLE_SET_ALIGN_PERCENT,
        TABLE_SET_ELLIPSIZE_PERCENT,
        TABLE_SET_COLOR,
        TABLE_SET_URL,
        TABLE_SET_UPPERCASE,

        _TABLE_DATA_TYPE_INVALID = -1,
} TableDataType;

/* PIDs are just 32bit signed integers on Linux */
#define TABLE_PID TABLE_INT32
assert_cc(sizeof(pid_t) == sizeof(int32_t));

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
int table_add_cell_stringf(Table *t, TableCell **ret_cell, const char *format, ...) _printf_(3, 4);

int table_fill_empty(Table *t, size_t until_column);

int table_dup_cell(Table *t, TableCell *cell);

int table_set_minimum_width(Table *t, TableCell *cell, size_t minimum_width);
int table_set_maximum_width(Table *t, TableCell *cell, size_t maximum_width);
int table_set_weight(Table *t, TableCell *cell, unsigned weight);
int table_set_align_percent(Table *t, TableCell *cell, unsigned percent);
int table_set_ellipsize_percent(Table *t, TableCell *cell, unsigned percent);
int table_set_color(Table *t, TableCell *cell, const char *color);
int table_set_url(Table *t, TableCell *cell, const char *url);
int table_set_uppercase(Table *t, TableCell *cell, bool b);

int table_update(Table *t, TableCell *cell, TableDataType type, const void *data);

int table_add_many_internal(Table *t, TableDataType first_type, ...);
#define table_add_many(t, ...) table_add_many_internal(t, __VA_ARGS__, _TABLE_DATA_TYPE_MAX)

void table_set_header(Table *table, bool b);
void table_set_width(Table *t, size_t width);
int table_set_empty_string(Table *t, const char *empty);
int table_set_display(Table *t, size_t first_column, ...);
int table_set_sort(Table *t, size_t first_column, ...);
int table_set_reverse(Table *t, size_t column, bool b);

int table_print(Table *t, FILE *f);
int table_format(Table *t, char **ret);

static inline TableCell* TABLE_HEADER_CELL(size_t i) {
        return SIZE_TO_PTR(i + 1);
}

size_t table_get_rows(Table *t);
size_t table_get_columns(Table *t);

TableCell *table_get_cell(Table *t, size_t row, size_t column);

const void *table_get(Table *t, TableCell *cell);
const void *table_get_at(Table *t, size_t row, size_t column);

int table_to_json(Table *t, JsonVariant **ret);
int table_print_json(Table *t, FILE *f, JsonFormatFlags json_flags);
