/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include "json.h"
#include "macro.h"
#include "pager.h"

typedef enum TableDataType {
        TABLE_EMPTY,
        TABLE_STRING,
        TABLE_HEADER,              /* in regular mode: the cells in the first row, that carry the column names */
        TABLE_FIELD,               /* in vertical mode: the cells in the first column, that carry the field names */
        TABLE_STRV,
        TABLE_STRV_WRAPPED,
        TABLE_PATH,
        TABLE_PATH_BASENAME,       /* like TABLE_PATH, but display only last path element (i.e. the "basename") in regular output */
        TABLE_BOOLEAN,
        TABLE_BOOLEAN_CHECKMARK,
        TABLE_TIMESTAMP,
        TABLE_TIMESTAMP_UTC,
        TABLE_TIMESTAMP_RELATIVE,
        TABLE_TIMESTAMP_RELATIVE_MONOTONIC,
        TABLE_TIMESTAMP_LEFT,
        TABLE_TIMESTAMP_DATE,
        TABLE_TIMESPAN,
        TABLE_TIMESPAN_MSEC,
        TABLE_TIMESPAN_DAY,
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
        TABLE_UINT32_HEX,
        TABLE_UINT64,
        TABLE_UINT64_HEX,
        TABLE_PERCENT,
        TABLE_IFINDEX,
        TABLE_IN_ADDR,  /* Takes a union in_addr_union (or a struct in_addr) */
        TABLE_IN6_ADDR, /* Takes a union in_addr_union (or a struct in6_addr) */
        TABLE_ID128,
        TABLE_UUID,
        TABLE_UID,
        TABLE_GID,
        TABLE_PID,
        TABLE_SIGNAL,
        TABLE_MODE,            /* as in UNIX file mode (mode_t), in typical octal output */
        TABLE_MODE_INODE_TYPE, /* also mode_t, but displays only the inode type as string */
        TABLE_DEVNUM,          /* a dev_t, displayed in the usual major:minor way */
        _TABLE_DATA_TYPE_MAX,

        /* The following are not really data types, but commands for table_add_cell_many() to make changes to
         * a cell just added. */
        TABLE_SET_MINIMUM_WIDTH,
        TABLE_SET_MAXIMUM_WIDTH,
        TABLE_SET_WEIGHT,
        TABLE_SET_ALIGN_PERCENT,
        TABLE_SET_ELLIPSIZE_PERCENT,
        TABLE_SET_COLOR,
        TABLE_SET_RGAP_COLOR,
        TABLE_SET_BOTH_COLORS,
        TABLE_SET_UNDERLINE,
        TABLE_SET_RGAP_UNDERLINE,
        TABLE_SET_BOTH_UNDERLINES,
        TABLE_SET_URL,
        TABLE_SET_UPPERCASE,

        _TABLE_DATA_TYPE_INVALID = -EINVAL,
} TableDataType;

typedef enum TableErsatz {
        TABLE_ERSATZ_EMPTY,
        TABLE_ERSATZ_DASH,
        TABLE_ERSATZ_UNSET,
        TABLE_ERSATZ_NA,
        _TABLE_ERSATZ_MAX,
} TableErsatz;

typedef struct Table Table;
typedef struct TableCell TableCell;

Table *table_new_internal(const char *first_header, ...) _sentinel_;
#define table_new(...) table_new_internal(__VA_ARGS__, NULL)
Table *table_new_raw(size_t n_columns);
Table *table_new_vertical(void);
Table *table_unref(Table *t);

DEFINE_TRIVIAL_CLEANUP_FUNC(Table*, table_unref);

int table_add_cell_full(Table *t, TableCell **ret_cell, TableDataType type, const void *data, size_t minimum_width, size_t maximum_width, unsigned weight, unsigned align_percent, unsigned ellipsize_percent);
static inline int table_add_cell(Table *t, TableCell **ret_cell, TableDataType type, const void *data) {
        return table_add_cell_full(t, ret_cell, type, data, SIZE_MAX, SIZE_MAX, UINT_MAX, UINT_MAX, UINT_MAX);
}
int table_add_cell_stringf_full(Table *t, TableCell **ret_cell, TableDataType type, const char *format, ...) _printf_(4, 5);
#define table_add_cell_stringf(t, ret_cell, format, ...) table_add_cell_stringf_full(t, ret_cell, TABLE_STRING, format, __VA_ARGS__)

int table_fill_empty(Table *t, size_t until_column);

int table_dup_cell(Table *t, TableCell *cell);

int table_set_minimum_width(Table *t, TableCell *cell, size_t minimum_width);
int table_set_maximum_width(Table *t, TableCell *cell, size_t maximum_width);
int table_set_weight(Table *t, TableCell *cell, unsigned weight);
int table_set_align_percent(Table *t, TableCell *cell, unsigned percent);
int table_set_ellipsize_percent(Table *t, TableCell *cell, unsigned percent);
int table_set_color(Table *t, TableCell *cell, const char *color);
int table_set_rgap_color(Table *t, TableCell *cell, const char *color);
int table_set_underline(Table *t, TableCell *cell, bool b);
int table_set_rgap_underline(Table *t, TableCell *cell, bool b);
int table_set_url(Table *t, TableCell *cell, const char *url);
int table_set_uppercase(Table *t, TableCell *cell, bool b);

int table_update(Table *t, TableCell *cell, TableDataType type, const void *data);

int table_add_many_internal(Table *t, TableDataType first_type, ...);
#define table_add_many(t, ...) table_add_many_internal(t, __VA_ARGS__, _TABLE_DATA_TYPE_MAX)

void table_set_header(Table *table, bool b);
void table_set_width(Table *t, size_t width);
void table_set_cell_height_max(Table *t, size_t height);
void table_set_ersatz_string(Table *t, TableErsatz ersatz);
int table_set_display_internal(Table *t, size_t first_column, ...);
#define table_set_display(...) table_set_display_internal(__VA_ARGS__, SIZE_MAX)
int table_set_sort_internal(Table *t, size_t first_column, ...);
#define table_set_sort(...) table_set_sort_internal(__VA_ARGS__, SIZE_MAX)
int table_set_reverse(Table *t, size_t column, bool b);
int table_hide_column_from_display_internal(Table *t, ...);
#define table_hide_column_from_display(t, ...) table_hide_column_from_display_internal(t, __VA_ARGS__, (size_t) -1)

int table_print(Table *t, FILE *f);
int table_format(Table *t, char **ret);

static inline TableCell* TABLE_HEADER_CELL(size_t i) {
        return SIZE_TO_PTR(i + 1);
}

size_t table_get_rows(Table *t);
static inline bool table_isempty(Table *t) {
        if (!t)
                return true;

        return table_get_rows(t) <= 1;
}
size_t table_get_columns(Table *t);

size_t table_get_current_column(Table *t);

TableCell *table_get_cell(Table *t, size_t row, size_t column);

const void *table_get(Table *t, TableCell *cell);
const void *table_get_at(Table *t, size_t row, size_t column);

int table_to_json(Table *t, JsonVariant **ret);
int table_print_json(Table *t, FILE *f, JsonFormatFlags json_flags);

int table_print_with_pager(Table *t, JsonFormatFlags json_format_flags, PagerFlags pager_flags, bool show_header);

int table_set_json_field_name(Table *t, size_t idx, const char *name);

#define table_log_add_error(r) \
        log_error_errno(r, "Failed to add cells to table: %m")

#define table_log_print_error(r) \
        log_error_errno(r, "Failed to print table: %m")

#define table_log_sort_error(r) \
        log_error_errno(r, "Failed to sort table: %m")
