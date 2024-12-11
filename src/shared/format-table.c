/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <ctype.h>
#include <net/if.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-ifname.h"
#include "format-table.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "gunicode.h"
#include "id128-util.h"
#include "in-addr-util.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "pager.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "process-util.h"
#include "signal-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "terminal-util.h"
#include "time-util.h"
#include "user-util.h"
#include "utf8.h"

#define DEFAULT_WEIGHT 100

/*
   A few notes on implementation details:

 - TableCell is a 'fake' structure, it's just used as data type to pass references to specific cell positions in the
   table. It can be easily converted to an index number and back.

 - TableData is where the actual data is stored: it encapsulates the data and formatting for a specific cell. It's
   'pseudo-immutable' and ref-counted. When a cell's data's formatting is to be changed, we duplicate the object if the
   ref-counting is larger than 1. Note that TableData and its ref-counting is mostly not visible to the outside. The
   outside only sees Table and TableCell.

 - The Table object stores a simple one-dimensional array of references to TableData objects, one row after the
   previous one.

 - There's no special concept of a "row" or "column" in the table, and no special concept of the "header" row. It's all
   derived from the cell index: we know how many cells are to be stored in a row, and can determine the rest from
   that. The first row is always the header row. If header display is turned off we simply skip outputting the first
   row. Also, when sorting rows we always leave the first row where it is, as the header shouldn't move.

 - Note because there's no row and no column object some properties that might be appropriate as row/column properties
   are exposed as cell properties instead. For example, the "weight" of a column (which is used to determine where to
   add/remove space preferable when expanding/compressing tables horizontally) is actually made the "weight" of a
   cell. Given that we usually need it per-column though we will calculate the average across every cell of the column
   instead.

 - To make things easy, when cells are added without any explicit configured formatting, then we'll copy the formatting
   from the same cell in the previous cell. This is particularly useful for the "weight" of the cell (see above), as
   this means setting the weight of the cells of the header row will nicely propagate to all cells in the other rows.
*/

typedef struct TableData {
        unsigned n_ref;
        TableDataType type;

        size_t minimum_width;       /* minimum width for the column */
        size_t maximum_width;       /* maximum width for the column */
        size_t formatted_for_width; /* the width we tried to format for */
        unsigned weight;            /* the horizontal weight for this column, in case the table is expanded/compressed */
        unsigned ellipsize_percent; /* 0 … 100, where to place the ellipsis when compression is needed */
        unsigned align_percent;     /* 0 … 100, where to pad with spaces when expanding is needed. 0: left-aligned, 100: right-aligned */

        bool uppercase:1;           /* Uppercase string on display */
        bool underline:1;
        bool rgap_underline:1;

        const char *color;          /* ANSI color string to use for this cell. When written to terminal should not move cursor. Will automatically be reset after the cell */
        const char *rgap_color;     /* The ANSI color to use for the gap right of this cell. Usually used to underline entire rows in a gapless fashion */
        char *url;                  /* A URL to use for a clickable hyperlink */
        char *formatted;            /* A cached textual representation of the cell data, before ellipsation/alignment */

        union {
                uint8_t data[0];    /* data is generic array */
                bool boolean;
                usec_t timestamp;
                usec_t timespan;
                uint64_t size;
                char string[0];
                char **strv;
                int int_val;
                int8_t int8;
                int16_t int16;
                int32_t int32;
                int64_t int64;
                unsigned uint_val;
                uint8_t uint8;
                uint16_t uint16;
                uint32_t uint32;
                uint64_t uint64;
                int percent;        /* we use 'int' as datatype for percent values in order to match the result of parse_percent() */
                int ifindex;
                union in_addr_union address;
                sd_id128_t id128;
                uid_t uid;
                gid_t gid;
                pid_t pid;
                mode_t mode;
                dev_t devnum;
                /* … add more here as we start supporting more cell data types … */
        };
} TableData;

static size_t TABLE_CELL_TO_INDEX(TableCell *cell) {
        size_t i;

        assert(cell);

        i = PTR_TO_SIZE(cell);
        assert(i > 0);

        return i-1;
}

static TableCell* TABLE_INDEX_TO_CELL(size_t index) {
        assert(index != SIZE_MAX);
        return SIZE_TO_PTR(index + 1);
}

struct Table {
        size_t n_columns;
        size_t n_cells;

        bool header;   /* Whether to show the header row? */
        bool vertical; /* Whether to field names are on the left rather than the first line */

        TableErsatz ersatz; /* What to show when we have an empty cell or an invalid value that cannot be rendered. */

        size_t width;  /* If == 0 format this as wide as necessary. If SIZE_MAX format this to console
                        * width or less wide, but not wider. Otherwise the width to format this table in. */
        size_t cell_height_max; /* Maximum number of lines per cell. (If there are more, ellipsis is shown. If SIZE_MAX then no limit is set, the default. == 0 is not allowed.) */

        TableData **data;

        size_t *display_map;  /* List of columns to show (by their index). It's fine if columns are listed multiple times or not at all */
        size_t n_display_map;

        size_t *sort_map;     /* The columns to order rows by, in order of preference. */
        size_t n_sort_map;

        char **json_fields;
        size_t n_json_fields;

        bool *reverse_map;
};

Table *table_new_raw(size_t n_columns) {
        _cleanup_(table_unrefp) Table *t = NULL;

        assert(n_columns > 0);

        t = new(Table, 1);
        if (!t)
                return NULL;

        *t = (Table) {
                .n_columns = n_columns,
                .header = true,
                .width = SIZE_MAX,
                .cell_height_max = SIZE_MAX,
                .ersatz = TABLE_ERSATZ_EMPTY,
        };

        return TAKE_PTR(t);
}

Table *table_new_internal(const char *first_header, ...) {
        _cleanup_(table_unrefp) Table *t = NULL;
        size_t n_columns = 1;
        va_list ap;
        int r;

        assert(first_header);

        va_start(ap, first_header);
        for (;;) {
                if (!va_arg(ap, const char*))
                        break;

                n_columns++;
        }
        va_end(ap);

        t = table_new_raw(n_columns);
        if (!t)
                return NULL;

        va_start(ap, first_header);
        for (const char *h = first_header; h; h = va_arg(ap, const char*)) {
                TableCell *cell;

                r = table_add_cell(t, &cell, TABLE_HEADER, h);
                if (r < 0) {
                        va_end(ap);
                        return NULL;
                }
        }
        va_end(ap);

        assert(t->n_columns == t->n_cells);
        return TAKE_PTR(t);
}

Table *table_new_vertical(void) {
        _cleanup_(table_unrefp) Table *t = NULL;
        TableCell *cell;

        t = table_new_raw(2);
        if (!t)
                return NULL;

        t->vertical = true;
        t->header = false;

        if (table_add_cell(t, &cell, TABLE_HEADER, "key") < 0)
                return NULL;

        if (table_set_align_percent(t, cell, 100) < 0)
                return NULL;

        if (table_add_cell(t, &cell, TABLE_HEADER, "value") < 0)
                return NULL;

        if (table_set_align_percent(t, cell, 0) < 0)
                return NULL;

        return TAKE_PTR(t);
}

static TableData *table_data_free(TableData *d) {
        assert(d);

        free(d->formatted);
        free(d->url);

        if (IN_SET(d->type, TABLE_STRV, TABLE_STRV_WRAPPED))
                strv_free(d->strv);

        return mfree(d);
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(TableData, table_data, table_data_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(TableData*, table_data_unref);

Table *table_unref(Table *t) {
        if (!t)
                return NULL;

        for (size_t i = 0; i < t->n_cells; i++)
                table_data_unref(t->data[i]);

        free(t->data);
        free(t->display_map);
        free(t->sort_map);
        free(t->reverse_map);

        for (size_t i = 0; i < t->n_json_fields; i++)
                free(t->json_fields[i]);

        free(t->json_fields);

        return mfree(t);
}

static size_t table_data_size(TableDataType type, const void *data) {

        switch (type) {

        case TABLE_EMPTY:
                return 0;

        case TABLE_STRING:
        case TABLE_PATH:
        case TABLE_PATH_BASENAME:
        case TABLE_FIELD:
        case TABLE_HEADER:
                return strlen(data) + 1;

        case TABLE_STRV:
        case TABLE_STRV_WRAPPED:
                return sizeof(char **);

        case TABLE_BOOLEAN_CHECKMARK:
        case TABLE_BOOLEAN:
                return sizeof(bool);

        case TABLE_TIMESTAMP:
        case TABLE_TIMESTAMP_UTC:
        case TABLE_TIMESTAMP_RELATIVE:
        case TABLE_TIMESTAMP_RELATIVE_MONOTONIC:
        case TABLE_TIMESTAMP_LEFT:
        case TABLE_TIMESTAMP_DATE:
        case TABLE_TIMESPAN:
        case TABLE_TIMESPAN_MSEC:
        case TABLE_TIMESPAN_DAY:
                return sizeof(usec_t);

        case TABLE_SIZE:
        case TABLE_INT64:
        case TABLE_UINT64:
        case TABLE_UINT64_HEX:
        case TABLE_BPS:
                return sizeof(uint64_t);

        case TABLE_INT32:
        case TABLE_UINT32:
        case TABLE_UINT32_HEX:
                return sizeof(uint32_t);

        case TABLE_INT16:
        case TABLE_UINT16:
                return sizeof(uint16_t);

        case TABLE_INT8:
        case TABLE_UINT8:
                return sizeof(uint8_t);

        case TABLE_INT:
        case TABLE_UINT:
        case TABLE_PERCENT:
        case TABLE_IFINDEX:
        case TABLE_SIGNAL:
                return sizeof(int);

        case TABLE_IN_ADDR:
                return sizeof(struct in_addr);

        case TABLE_IN6_ADDR:
                return sizeof(struct in6_addr);

        case TABLE_UUID:
        case TABLE_ID128:
                return sizeof(sd_id128_t);

        case TABLE_UID:
                return sizeof(uid_t);
        case TABLE_GID:
                return sizeof(gid_t);
        case TABLE_PID:
                return sizeof(pid_t);

        case TABLE_MODE:
        case TABLE_MODE_INODE_TYPE:
                return sizeof(mode_t);

        case TABLE_DEVNUM:
                return sizeof(dev_t);

        default:
                assert_not_reached();
        }
}

static bool table_data_matches(
                TableData *d,
                TableDataType type,
                const void *data,
                size_t minimum_width,
                size_t maximum_width,
                unsigned weight,
                unsigned align_percent,
                unsigned ellipsize_percent,
                bool uppercase) {

        size_t k, l;
        assert(d);

        if (d->type != type)
                return false;

        if (d->minimum_width != minimum_width)
                return false;

        if (d->maximum_width != maximum_width)
                return false;

        if (d->weight != weight)
                return false;

        if (d->align_percent != align_percent)
                return false;

        if (d->ellipsize_percent != ellipsize_percent)
                return false;

        if (d->uppercase != uppercase)
                return false;

        /* If a color/url is set, refuse to merge */
        if (d->color || d->rgap_color || d->underline || d->rgap_underline)
                return false;
        if (d->url)
                return false;

        k = table_data_size(type, data);
        l = table_data_size(d->type, d->data);
        if (k != l)
                return false;

        return memcmp_safe(data, d->data, l) == 0;
}

static TableData *table_data_new(
                TableDataType type,
                const void *data,
                size_t minimum_width,
                size_t maximum_width,
                unsigned weight,
                unsigned align_percent,
                unsigned ellipsize_percent,
                bool uppercase) {

        _cleanup_free_ TableData *d = NULL;
        size_t data_size;

        data_size = table_data_size(type, data);

        d = malloc0(offsetof(TableData, data) + data_size);
        if (!d)
                return NULL;

        d->n_ref = 1;
        d->type = type;
        d->minimum_width = minimum_width;
        d->maximum_width = maximum_width;
        d->weight = weight;
        d->align_percent = align_percent;
        d->ellipsize_percent = ellipsize_percent;
        d->uppercase = uppercase;

        if (IN_SET(type, TABLE_STRV, TABLE_STRV_WRAPPED)) {
                d->strv = strv_copy(data);
                if (!d->strv)
                        return NULL;
        } else
                memcpy_safe(d->data, data, data_size);

        return TAKE_PTR(d);
}

int table_add_cell_full(
                Table *t,
                TableCell **ret_cell,
                TableDataType type,
                const void *data,
                size_t minimum_width,
                size_t maximum_width,
                unsigned weight,
                unsigned align_percent,
                unsigned ellipsize_percent) {

        _cleanup_(table_data_unrefp) TableData *d = NULL;
        bool uppercase;
        TableData *p;

        assert(t);
        assert(type >= 0);
        assert(type < _TABLE_DATA_TYPE_MAX);

        /* Special rule: patch NULL data fields to the empty field */
        if (!data)
                type = TABLE_EMPTY;

        /* Determine the cell adjacent to the current one, but one row up */
        if (t->n_cells >= t->n_columns)
                assert_se(p = t->data[t->n_cells - t->n_columns]);
        else
                p = NULL;

        /* If formatting parameters are left unspecified, copy from the previous row */
        if (minimum_width == SIZE_MAX)
                minimum_width = p ? p->minimum_width : 1;

        if (weight == UINT_MAX)
                weight = p ? p->weight : DEFAULT_WEIGHT;

        if (align_percent == UINT_MAX)
                align_percent = p ? p->align_percent : 0;

        if (ellipsize_percent == UINT_MAX)
                ellipsize_percent = p ? p->ellipsize_percent : 100;

        assert(align_percent <= 100);
        assert(ellipsize_percent <= 100);

        uppercase = type == TABLE_HEADER;

        /* Small optimization: Pretty often adjacent cells in two subsequent lines have the same data and
         * formatting. Let's see if we can reuse the cell data and ref it once more. */

        if (p && table_data_matches(p, type, data, minimum_width, maximum_width, weight, align_percent, ellipsize_percent, uppercase))
                d = table_data_ref(p);
        else {
                d = table_data_new(type, data, minimum_width, maximum_width, weight, align_percent, ellipsize_percent, uppercase);
                if (!d)
                        return -ENOMEM;
        }

        if (!GREEDY_REALLOC(t->data, MAX(t->n_cells + 1, t->n_columns)))
                return -ENOMEM;

        if (ret_cell)
                *ret_cell = TABLE_INDEX_TO_CELL(t->n_cells);

        t->data[t->n_cells++] = TAKE_PTR(d);

        return 0;
}

int table_add_cell_stringf_full(Table *t, TableCell **ret_cell, TableDataType dt, const char *format, ...) {
        _cleanup_free_ char *buffer = NULL;
        va_list ap;
        int r;

        assert(t);
        assert(IN_SET(dt, TABLE_STRING, TABLE_PATH, TABLE_PATH_BASENAME, TABLE_FIELD, TABLE_HEADER));

        va_start(ap, format);
        r = vasprintf(&buffer, format, ap);
        va_end(ap);
        if (r < 0)
                return -ENOMEM;

        return table_add_cell(t, ret_cell, dt, buffer);
}

int table_fill_empty(Table *t, size_t until_column) {
        int r;

        assert(t);

        /* Fill the rest of the current line with empty cells until we reach the specified column. Will add
         * at least one cell. Pass 0 in order to fill a line to the end or insert an empty line. */

        if (until_column >= t->n_columns)
                return -EINVAL;

        do {
                r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return r;

        } while ((t->n_cells % t->n_columns) != until_column);

        return 0;
}

int table_dup_cell(Table *t, TableCell *cell) {
        size_t i;

        assert(t);

        /* Add the data of the specified cell a second time as a new cell to the end. */

        i = TABLE_CELL_TO_INDEX(cell);
        if (i >= t->n_cells)
                return -ENXIO;

        if (!GREEDY_REALLOC(t->data, MAX(t->n_cells + 1, t->n_columns)))
                return -ENOMEM;

        t->data[t->n_cells++] = table_data_ref(t->data[i]);
        return 0;
}

static int table_dedup_cell(Table *t, TableCell *cell) {
        _cleanup_free_ char *curl = NULL;
        TableData *nd, *od;
        size_t i;

        assert(t);

        /* Helper call that ensures the specified cell's data object has a ref count of 1, which we can use before
         * changing a cell's formatting without effecting every other cell's formatting that shares the same data */

        i = TABLE_CELL_TO_INDEX(cell);
        if (i >= t->n_cells)
                return -ENXIO;

        assert_se(od = t->data[i]);
        if (od->n_ref == 1)
                return 0;

        assert(od->n_ref > 1);

        if (od->url) {
                curl = strdup(od->url);
                if (!curl)
                        return -ENOMEM;
        }

        nd = table_data_new(
                        od->type,
                        od->data,
                        od->minimum_width,
                        od->maximum_width,
                        od->weight,
                        od->align_percent,
                        od->ellipsize_percent,
                        od->uppercase);
        if (!nd)
                return -ENOMEM;

        nd->color = od->color;
        nd->rgap_color = od->rgap_color;
        nd->underline = od->underline;
        nd->rgap_underline = od->rgap_underline;
        nd->url = TAKE_PTR(curl);

        table_data_unref(od);
        t->data[i] = nd;

        assert(nd->n_ref == 1);

        return 1;
}

static TableData *table_get_data(Table *t, TableCell *cell) {
        size_t i;

        assert(t);
        assert(cell);

        /* Get the data object of the specified cell, or NULL if it doesn't exist */

        i = TABLE_CELL_TO_INDEX(cell);
        if (i >= t->n_cells)
                return NULL;

        assert(t->data[i]);
        assert(t->data[i]->n_ref > 0);

        return t->data[i];
}

int table_set_minimum_width(Table *t, TableCell *cell, size_t minimum_width) {
        int r;

        assert(t);
        assert(cell);

        if (minimum_width == SIZE_MAX)
                minimum_width = 1;

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->minimum_width = minimum_width;
        return 0;
}

int table_set_maximum_width(Table *t, TableCell *cell, size_t maximum_width) {
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->maximum_width = maximum_width;
        return 0;
}

int table_set_weight(Table *t, TableCell *cell, unsigned weight) {
        int r;

        assert(t);
        assert(cell);

        if (weight == UINT_MAX)
                weight = DEFAULT_WEIGHT;

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->weight = weight;
        return 0;
}

int table_set_align_percent(Table *t, TableCell *cell, unsigned percent) {
        int r;

        assert(t);
        assert(cell);

        if (percent == UINT_MAX)
                percent = 0;

        assert(percent <= 100);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->align_percent = percent;
        return 0;
}

int table_set_ellipsize_percent(Table *t, TableCell *cell, unsigned percent) {
        int r;

        assert(t);
        assert(cell);

        if (percent == UINT_MAX)
                percent = 100;

        assert(percent <= 100);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->ellipsize_percent = percent;
        return 0;
}

int table_set_color(Table *t, TableCell *cell, const char *color) {
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->color = empty_to_null(color);
        return 0;
}

int table_set_rgap_color(Table *t, TableCell *cell, const char *color) {
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        table_get_data(t, cell)->rgap_color = empty_to_null(color);
        return 0;
}

int table_set_underline(Table *t, TableCell *cell, bool b) {
        TableData *d;
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        assert_se(d = table_get_data(t, cell));

        if (d->underline == b)
                return 0;

        d->underline = b;
        return 1;
}

int table_set_rgap_underline(Table *t, TableCell *cell, bool b) {
        TableData *d;
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        assert_se(d = table_get_data(t, cell));

        if (d->rgap_underline == b)
                return 0;

        d->rgap_underline = b;
        return 1;
}

int table_set_url(Table *t, TableCell *cell, const char *url) {
        _cleanup_free_ char *copy = NULL;
        int r;

        assert(t);
        assert(cell);

        if (url) {
                copy = strdup(url);
                if (!copy)
                        return -ENOMEM;
        }

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        return free_and_replace(table_get_data(t, cell)->url, copy);
}

int table_set_uppercase(Table *t, TableCell *cell, bool b) {
        TableData *d;
        int r;

        assert(t);
        assert(cell);

        r = table_dedup_cell(t, cell);
        if (r < 0)
                return r;

        assert_se(d = table_get_data(t, cell));

        if (d->uppercase == b)
                return 0;

        d->formatted = mfree(d->formatted);
        d->uppercase = b;
        return 1;
}

int table_update(Table *t, TableCell *cell, TableDataType type, const void *data) {
        _cleanup_free_ char *curl = NULL;
        TableData *nd, *od;
        size_t i;

        assert(t);
        assert(cell);

        i = TABLE_CELL_TO_INDEX(cell);
        if (i >= t->n_cells)
                return -ENXIO;

        assert_se(od = t->data[i]);

        if (od->url) {
                curl = strdup(od->url);
                if (!curl)
                        return -ENOMEM;
        }

        nd = table_data_new(
                        type,
                        data,
                        od->minimum_width,
                        od->maximum_width,
                        od->weight,
                        od->align_percent,
                        od->ellipsize_percent,
                        od->uppercase);
        if (!nd)
                return -ENOMEM;

        nd->color = od->color;
        nd->rgap_color = od->rgap_color;
        nd->underline = od->underline;
        nd->rgap_underline = od->rgap_underline;
        nd->url = TAKE_PTR(curl);

        table_data_unref(od);
        t->data[i] = nd;

        return 0;
}

int table_add_many_internal(Table *t, TableDataType first_type, ...) {
        TableCell *last_cell = NULL;
        va_list ap;
        int r;

        assert(t);
        assert(first_type >= 0);
        assert(first_type < _TABLE_DATA_TYPE_MAX);

        va_start(ap, first_type);

        for (TableDataType type = first_type;; type = va_arg(ap, TableDataType)) {
                const void *data;
                union {
                        uint64_t size;
                        usec_t usec;
                        int int_val;
                        int8_t int8;
                        int16_t int16;
                        int32_t int32;
                        int64_t int64;
                        unsigned uint_val;
                        uint8_t uint8;
                        uint16_t uint16;
                        uint32_t uint32;
                        uint64_t uint64;
                        int percent;
                        int ifindex;
                        bool b;
                        union in_addr_union address;
                        sd_id128_t id128;
                        uid_t uid;
                        gid_t gid;
                        pid_t pid;
                        mode_t mode;
                        dev_t devnum;
                } buffer;

                switch (type) {

                case TABLE_EMPTY:
                        data = NULL;
                        break;

                case TABLE_STRING:
                case TABLE_PATH:
                case TABLE_PATH_BASENAME:
                case TABLE_FIELD:
                case TABLE_HEADER:
                        data = va_arg(ap, const char *);
                        break;

                case TABLE_STRV:
                case TABLE_STRV_WRAPPED:
                        data = va_arg(ap, char * const *);
                        break;

                case TABLE_BOOLEAN_CHECKMARK:
                case TABLE_BOOLEAN:
                        buffer.b = va_arg(ap, int);
                        data = &buffer.b;
                        break;

                case TABLE_TIMESTAMP:
                case TABLE_TIMESTAMP_UTC:
                case TABLE_TIMESTAMP_RELATIVE:
                case TABLE_TIMESTAMP_RELATIVE_MONOTONIC:
                case TABLE_TIMESTAMP_LEFT:
                case TABLE_TIMESTAMP_DATE:
                case TABLE_TIMESPAN:
                case TABLE_TIMESPAN_MSEC:
                case TABLE_TIMESPAN_DAY:
                        buffer.usec = va_arg(ap, usec_t);
                        data = &buffer.usec;
                        break;

                case TABLE_SIZE:
                case TABLE_BPS:
                        buffer.size = va_arg(ap, uint64_t);
                        data = &buffer.size;
                        break;

                case TABLE_INT:
                case TABLE_SIGNAL:
                        buffer.int_val = va_arg(ap, int);
                        data = &buffer.int_val;
                        break;

                case TABLE_INT8: {
                        int x = va_arg(ap, int);
                        assert(x >= INT8_MIN && x <= INT8_MAX);

                        buffer.int8 = x;
                        data = &buffer.int8;
                        break;
                }

                case TABLE_INT16: {
                        int x = va_arg(ap, int);
                        assert(x >= INT16_MIN && x <= INT16_MAX);

                        buffer.int16 = x;
                        data = &buffer.int16;
                        break;
                }

                case TABLE_INT32:
                        buffer.int32 = va_arg(ap, int32_t);
                        data = &buffer.int32;
                        break;

                case TABLE_INT64:
                        buffer.int64 = va_arg(ap, int64_t);
                        data = &buffer.int64;
                        break;

                case TABLE_UINT:
                        buffer.uint_val = va_arg(ap, unsigned);
                        data = &buffer.uint_val;
                        break;

                case TABLE_UINT8: {
                        unsigned x = va_arg(ap, unsigned);
                        assert(x <= UINT8_MAX);

                        buffer.uint8 = x;
                        data = &buffer.uint8;
                        break;
                }

                case TABLE_UINT16: {
                        unsigned x = va_arg(ap, unsigned);
                        assert(x <= UINT16_MAX);

                        buffer.uint16 = x;
                        data = &buffer.uint16;
                        break;
                }

                case TABLE_UINT32:
                case TABLE_UINT32_HEX:
                        buffer.uint32 = va_arg(ap, uint32_t);
                        data = &buffer.uint32;
                        break;

                case TABLE_UINT64:
                case TABLE_UINT64_HEX:
                        buffer.uint64 = va_arg(ap, uint64_t);
                        data = &buffer.uint64;
                        break;

                case TABLE_PERCENT:
                        buffer.percent = va_arg(ap, int);
                        data = &buffer.percent;
                        break;

                case TABLE_IFINDEX:
                        buffer.ifindex = va_arg(ap, int);
                        data = &buffer.ifindex;
                        break;

                case TABLE_IN_ADDR:
                        buffer.address = *va_arg(ap, union in_addr_union *);
                        data = &buffer.address.in;
                        break;

                case TABLE_IN6_ADDR:
                        buffer.address = *va_arg(ap, union in_addr_union *);
                        data = &buffer.address.in6;
                        break;

                case TABLE_UUID:
                case TABLE_ID128:
                        buffer.id128 = va_arg(ap, sd_id128_t);
                        data = &buffer.id128;
                        break;

                case TABLE_UID:
                        buffer.uid = va_arg(ap, uid_t);
                        data = &buffer.uid;
                        break;

                case TABLE_GID:
                        buffer.gid = va_arg(ap, gid_t);
                        data = &buffer.gid;
                        break;

                case TABLE_PID:
                        buffer.pid = va_arg(ap, pid_t);
                        data = &buffer.pid;
                        break;

                case TABLE_MODE:
                case TABLE_MODE_INODE_TYPE:
                        buffer.mode = va_arg(ap, mode_t);
                        data = &buffer.mode;
                        break;

                case TABLE_DEVNUM:
                        buffer.devnum = va_arg(ap, dev_t);
                        data = &buffer.devnum;
                        break;

                case TABLE_SET_MINIMUM_WIDTH: {
                        size_t w = va_arg(ap, size_t);

                        r = table_set_minimum_width(t, last_cell, w);
                        goto check;
                }

                case TABLE_SET_MAXIMUM_WIDTH: {
                        size_t w = va_arg(ap, size_t);
                        r = table_set_maximum_width(t, last_cell, w);
                        goto check;
                }

                case TABLE_SET_WEIGHT: {
                        unsigned w = va_arg(ap, unsigned);
                        r = table_set_weight(t, last_cell, w);
                        goto check;
                }

                case TABLE_SET_ALIGN_PERCENT: {
                        unsigned p = va_arg(ap, unsigned);
                        r = table_set_align_percent(t, last_cell, p);
                        goto check;
                }

                case TABLE_SET_ELLIPSIZE_PERCENT: {
                        unsigned p = va_arg(ap, unsigned);
                        r = table_set_ellipsize_percent(t, last_cell, p);
                        goto check;
                }

                case TABLE_SET_COLOR: {
                        const char *c = va_arg(ap, const char*);
                        r = table_set_color(t, last_cell, c);
                        goto check;
                }

                case TABLE_SET_RGAP_COLOR: {
                        const char *c = va_arg(ap, const char*);
                        r = table_set_rgap_color(t, last_cell, c);
                        goto check;
                }

                case TABLE_SET_BOTH_COLORS: {
                        const char *c = va_arg(ap, const char*);

                        r = table_set_color(t, last_cell, c);
                        if (r < 0) {
                                va_end(ap);
                                return r;
                        }

                        r = table_set_rgap_color(t, last_cell, c);
                        goto check;
                }

                case TABLE_SET_UNDERLINE: {
                        int u = va_arg(ap, int);
                        r = table_set_underline(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_RGAP_UNDERLINE: {
                        int u = va_arg(ap, int);
                        r = table_set_rgap_underline(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_BOTH_UNDERLINES: {
                        int u = va_arg(ap, int);

                        r = table_set_underline(t, last_cell, u);
                        if (r < 0) {
                                va_end(ap);
                                return r;
                        }

                        r = table_set_rgap_underline(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_URL: {
                        const char *u = va_arg(ap, const char*);
                        r = table_set_url(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_UPPERCASE: {
                        int u = va_arg(ap, int);
                        r = table_set_uppercase(t, last_cell, u);
                        goto check;
                }

                case TABLE_SET_JSON_FIELD_NAME: {
                        const char *n = va_arg(ap, const char*);
                        size_t idx;
                        if (t->vertical) {
                                assert(TABLE_CELL_TO_INDEX(last_cell) >= t->n_columns);
                                idx = TABLE_CELL_TO_INDEX(last_cell) / t->n_columns - 1;
                        } else {
                                idx = TABLE_CELL_TO_INDEX(last_cell);
                                assert(idx < t->n_columns);
                        }
                        r = table_set_json_field_name(t, idx, n);
                        goto check;
                }

                case _TABLE_DATA_TYPE_MAX:
                        /* Used as end marker */
                        va_end(ap);
                        return 0;

                default:
                        assert_not_reached();
                }

                r = table_add_cell(t, &last_cell, type, data);
        check:
                if (r < 0) {
                        va_end(ap);
                        return r;
                }
        }
}

void table_set_header(Table *t, bool b) {
        assert(t);

        t->header = b;
}

void table_set_width(Table *t, size_t width) {
        assert(t);

        t->width = width;
}

void table_set_cell_height_max(Table *t, size_t height) {
        assert(t);
        assert(height >= 1 || height == SIZE_MAX);

        t->cell_height_max = height;
}

void table_set_ersatz_string(Table *t, TableErsatz ersatz) {
        assert(t);
        assert(ersatz >= 0 && ersatz < _TABLE_ERSATZ_MAX);

        t->ersatz = ersatz;
}

static const char* table_ersatz_string(const Table *t) {
        switch (t->ersatz) {
        case TABLE_ERSATZ_EMPTY:
                return "";
        case TABLE_ERSATZ_DASH:
                return "-";
        case TABLE_ERSATZ_UNSET:
                return "(unset)";
        case TABLE_ERSATZ_NA:
                return "n/a";
        default:
                assert_not_reached();
        }
}

static int table_set_display_all(Table *t) {
        size_t *d;

        assert(t);

        /* Initialize the display map to the identity */

        d = reallocarray(t->display_map, t->n_columns, sizeof(size_t));
        if (!d)
                return -ENOMEM;

        for (size_t i = 0; i < t->n_columns; i++)
                d[i] = i;

        t->display_map = d;
        t->n_display_map = t->n_columns;

        return 0;
}

int table_set_display_internal(Table *t, size_t first_column, ...) {
        size_t column;
        va_list ap;

        assert(t);

        column = first_column;

        va_start(ap, first_column);
        for (;;) {
                assert(column < t->n_columns);

                if (!GREEDY_REALLOC(t->display_map, MAX(t->n_columns, t->n_display_map+1))) {
                        va_end(ap);
                        return -ENOMEM;
                }

                t->display_map[t->n_display_map++] = column;

                column = va_arg(ap, size_t);
                if (column == SIZE_MAX)
                        break;

        }
        va_end(ap);

        return 0;
}

int table_set_sort_internal(Table *t, size_t first_column, ...) {
        size_t column;
        va_list ap;

        assert(t);

        column = first_column;

        va_start(ap, first_column);
        for (;;) {
                assert(column < t->n_columns);

                if (!GREEDY_REALLOC(t->sort_map, MAX(t->n_columns, t->n_sort_map+1))) {
                        va_end(ap);
                        return -ENOMEM;
                }

                t->sort_map[t->n_sort_map++] = column;

                column = va_arg(ap, size_t);
                if (column == SIZE_MAX)
                        break;
        }
        va_end(ap);

        return 0;
}

int table_hide_column_from_display_internal(Table *t, ...) {
        size_t cur = 0;
        int r;

        assert(t);

        /* If the display map is empty, initialize it with all available columns */
        if (!t->display_map) {
                r = table_set_display_all(t);
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(i, t->display_map, t->n_display_map) {
                bool listed = false;
                va_list ap;

                va_start(ap, t);
                for (;;) {
                        size_t column;

                        column = va_arg(ap, size_t);
                        if (column == SIZE_MAX)
                                break;
                        if (column == *i) {
                                listed = true;
                                break;
                        }
                }
                va_end(ap);

                if (listed)
                        continue;

                t->display_map[cur++] = *i;
        }

        t->n_display_map = cur;

        return 0;
}

static int cell_data_compare(TableData *a, size_t index_a, TableData *b, size_t index_b) {
        int r;

        assert(a);
        assert(b);

        if (a->type == b->type) {

                /* We only define ordering for cells of the same data type. If cells with different data types are
                 * compared we follow the order the cells were originally added in */

                switch (a->type) {

                case TABLE_STRING:
                case TABLE_FIELD:
                case TABLE_HEADER:
                        return strcmp(a->string, b->string);

                case TABLE_PATH:
                case TABLE_PATH_BASENAME:
                        return path_compare(a->string, b->string);

                case TABLE_STRV:
                case TABLE_STRV_WRAPPED:
                        return strv_compare(a->strv, b->strv);

                case TABLE_BOOLEAN:
                        if (!a->boolean && b->boolean)
                                return -1;
                        if (a->boolean && !b->boolean)
                                return 1;
                        return 0;

                case TABLE_TIMESTAMP:
                case TABLE_TIMESTAMP_UTC:
                case TABLE_TIMESTAMP_RELATIVE:
                case TABLE_TIMESTAMP_RELATIVE_MONOTONIC:
                case TABLE_TIMESTAMP_LEFT:
                case TABLE_TIMESTAMP_DATE:
                        return CMP(a->timestamp, b->timestamp);

                case TABLE_TIMESPAN:
                case TABLE_TIMESPAN_MSEC:
                case TABLE_TIMESPAN_DAY:
                        return CMP(a->timespan, b->timespan);

                case TABLE_SIZE:
                case TABLE_BPS:
                        return CMP(a->size, b->size);

                case TABLE_INT:
                case TABLE_SIGNAL:
                        return CMP(a->int_val, b->int_val);

                case TABLE_INT8:
                        return CMP(a->int8, b->int8);

                case TABLE_INT16:
                        return CMP(a->int16, b->int16);

                case TABLE_INT32:
                        return CMP(a->int32, b->int32);

                case TABLE_INT64:
                        return CMP(a->int64, b->int64);

                case TABLE_UINT:
                        return CMP(a->uint_val, b->uint_val);

                case TABLE_UINT8:
                        return CMP(a->uint8, b->uint8);

                case TABLE_UINT16:
                        return CMP(a->uint16, b->uint16);

                case TABLE_UINT32:
                case TABLE_UINT32_HEX:
                        return CMP(a->uint32, b->uint32);

                case TABLE_UINT64:
                case TABLE_UINT64_HEX:
                        return CMP(a->uint64, b->uint64);

                case TABLE_PERCENT:
                        return CMP(a->percent, b->percent);

                case TABLE_IFINDEX:
                        return CMP(a->ifindex, b->ifindex);

                case TABLE_IN_ADDR:
                        return CMP(a->address.in.s_addr, b->address.in.s_addr);

                case TABLE_IN6_ADDR:
                        return memcmp(&a->address.in6, &b->address.in6, FAMILY_ADDRESS_SIZE(AF_INET6));

                case TABLE_UUID:
                case TABLE_ID128:
                        return memcmp(&a->id128, &b->id128, sizeof(sd_id128_t));

                case TABLE_UID:
                        return CMP(a->uid, b->uid);

                case TABLE_GID:
                        return CMP(a->gid, b->gid);

                case TABLE_PID:
                        return CMP(a->pid, b->pid);

                case TABLE_MODE:
                case TABLE_MODE_INODE_TYPE:
                        return CMP(a->mode, b->mode);

                case TABLE_DEVNUM:
                        r = CMP(major(a->devnum), major(b->devnum));
                        if (r != 0)
                                return r;

                        return CMP(minor(a->devnum), minor(b->devnum));

                default:
                        ;
                }
        }

        /* Generic fallback using the original order in which the cells where added. */
        return CMP(index_a, index_b);
}

static int table_data_compare(const size_t *a, const size_t *b, Table *t) {
        int r;

        assert(t);
        assert(t->sort_map);

        /* Make sure the header stays at the beginning */
        if (*a < t->n_columns && *b < t->n_columns)
                return 0;
        if (*a < t->n_columns)
                return -1;
        if (*b < t->n_columns)
                return 1;

        /* Order other lines by the sorting map */
        for (size_t i = 0; i < t->n_sort_map; i++) {
                TableData *d, *dd;

                d = t->data[*a + t->sort_map[i]];
                dd = t->data[*b + t->sort_map[i]];

                r = cell_data_compare(d, *a, dd, *b);
                if (r != 0)
                        return t->reverse_map && t->reverse_map[t->sort_map[i]] ? -r : r;
        }

        /* Order identical lines by the order there were originally added in */
        return CMP(*a, *b);
}

static char* format_strv_width(char **strv, size_t column_width) {
        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;

        f = memstream_init(&m);
        if (!f)
                return NULL;

        size_t position = 0;
        STRV_FOREACH(p, strv) {
                size_t our_len = utf8_console_width(*p); /* This returns -1 on invalid utf-8 (which shouldn't happen).
                                                          * If that happens, we'll just print one item per line. */

                if (position == 0) {
                        fputs(*p, f);
                        position = our_len;
                } else if (size_add(size_add(position, 1), our_len) <= column_width) {
                        fprintf(f, " %s", *p);
                        position = size_add(size_add(position, 1), our_len);
                } else {
                        fprintf(f, "\n%s", *p);
                        position = our_len;
                }
        }

        char *buf;
        if (memstream_finalize(&m, &buf, NULL) < 0)
                return NULL;

        return buf;
}

static const char *table_data_format(Table *t, TableData *d, bool avoid_uppercasing, size_t column_width, bool *have_soft) {
        assert(d);

        if (d->formatted &&
            /* Only TABLE_STRV_WRAPPED adjust based on column_width so far… */
            (d->type != TABLE_STRV_WRAPPED || d->formatted_for_width == column_width))
                return d->formatted;

        switch (d->type) {
        case TABLE_EMPTY:
                return table_ersatz_string(t);

        case TABLE_STRING:
        case TABLE_PATH:
        case TABLE_PATH_BASENAME:
        case TABLE_FIELD:
        case TABLE_HEADER: {
                _cleanup_free_ char *bn = NULL;
                const char *s;

                if (d->type == TABLE_PATH_BASENAME)
                        s = path_extract_filename(d->string, &bn) < 0 ? d->string : bn;
                else
                        s = d->string;

                if (d->uppercase && !avoid_uppercasing) {
                        d->formatted = new(char, strlen(s) + (d->type == TABLE_FIELD) + 1);
                        if (!d->formatted)
                                return NULL;

                        char *q = d->formatted;
                        for (const char *p = s; *p; p++)
                                *(q++) = (char) toupper((unsigned char) *p);

                        if (d->type == TABLE_FIELD)
                                *(q++) = ':';

                        *q = 0;
                        return d->formatted;
                } else if (d->type == TABLE_FIELD) {
                        d->formatted = strjoin(s, ":");
                        if (!d->formatted)
                                return NULL;

                        return d->formatted;
                }

                if (bn) {
                        d->formatted = TAKE_PTR(bn);
                        return d->formatted;
                }

                return d->string;
        }

        case TABLE_STRV:
                if (strv_isempty(d->strv))
                        return table_ersatz_string(t);

                d->formatted = strv_join(d->strv, "\n");
                if (!d->formatted)
                        return NULL;
                break;

        case TABLE_STRV_WRAPPED: {
                if (strv_isempty(d->strv))
                        return table_ersatz_string(t);

                char *buf = format_strv_width(d->strv, column_width);
                if (!buf)
                        return NULL;

                free_and_replace(d->formatted, buf);
                d->formatted_for_width = column_width;
                if (have_soft)
                        *have_soft = true;

                break;
        }

        case TABLE_BOOLEAN:
                return yes_no(d->boolean);

        case TABLE_BOOLEAN_CHECKMARK:
                return special_glyph(d->boolean ? SPECIAL_GLYPH_CHECK_MARK : SPECIAL_GLYPH_CROSS_MARK);

        case TABLE_TIMESTAMP:
        case TABLE_TIMESTAMP_UTC:
        case TABLE_TIMESTAMP_RELATIVE:
        case TABLE_TIMESTAMP_RELATIVE_MONOTONIC:
        case TABLE_TIMESTAMP_LEFT:
        case TABLE_TIMESTAMP_DATE: {
                _cleanup_free_ char *p = NULL;
                char *ret;

                p = new(char,
                        IN_SET(d->type, TABLE_TIMESTAMP_RELATIVE, TABLE_TIMESTAMP_RELATIVE_MONOTONIC, TABLE_TIMESTAMP_LEFT) ?
                                FORMAT_TIMESTAMP_RELATIVE_MAX : FORMAT_TIMESTAMP_MAX);
                if (!p)
                        return NULL;

                if (d->type == TABLE_TIMESTAMP)
                        ret = format_timestamp(p, FORMAT_TIMESTAMP_MAX, d->timestamp);
                else if (d->type == TABLE_TIMESTAMP_UTC)
                        ret = format_timestamp_style(p, FORMAT_TIMESTAMP_MAX, d->timestamp, TIMESTAMP_UTC);
                else if (d->type == TABLE_TIMESTAMP_DATE)
                        ret = format_timestamp_style(p, FORMAT_TIMESTAMP_MAX, d->timestamp, TIMESTAMP_DATE);
                else if (d->type == TABLE_TIMESTAMP_RELATIVE_MONOTONIC)
                        ret = format_timestamp_relative_monotonic(p, FORMAT_TIMESTAMP_RELATIVE_MAX, d->timestamp);
                else
                        ret = format_timestamp_relative_full(p, FORMAT_TIMESTAMP_RELATIVE_MAX,
                                                             d->timestamp, CLOCK_REALTIME,
                                                             /* implicit_left = */ d->type == TABLE_TIMESTAMP_LEFT);
                if (!ret)
                        return "-";

                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_TIMESPAN:
        case TABLE_TIMESPAN_MSEC:
        case TABLE_TIMESPAN_DAY: {
                _cleanup_free_ char *p = NULL;

                p = new(char, FORMAT_TIMESPAN_MAX);
                if (!p)
                        return NULL;

                if (!format_timespan(p, FORMAT_TIMESPAN_MAX, d->timespan,
                                     d->type == TABLE_TIMESPAN ? 0 :
                                     d->type == TABLE_TIMESPAN_MSEC ? USEC_PER_MSEC : USEC_PER_DAY))
                        return "-";

                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_SIZE: {
                _cleanup_free_ char *p = NULL;

                p = new(char, FORMAT_BYTES_MAX);
                if (!p)
                        return NULL;

                if (!format_bytes(p, FORMAT_BYTES_MAX, d->size))
                        return table_ersatz_string(t);

                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_BPS: {
                _cleanup_free_ char *p = NULL;
                size_t n;

                p = new(char, FORMAT_BYTES_MAX+2);
                if (!p)
                        return NULL;

                if (!format_bytes_full(p, FORMAT_BYTES_MAX, d->size, FORMAT_BYTES_BELOW_POINT))
                        return table_ersatz_string(t);

                n = strlen(p);
                strscpy(p + n, FORMAT_BYTES_MAX + 2 - n, "bps");

                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_INT: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->int_val) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%i", d->int_val);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_INT8: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->int8) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIi8, d->int8);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_INT16: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->int16) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIi16, d->int16);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_INT32: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->int32) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIi32, d->int32);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_INT64: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->int64) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIi64, d->int64);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_UINT: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->uint_val) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%u", d->uint_val);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_UINT8: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->uint8) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIu8, d->uint8);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_UINT16: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->uint16) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIu16, d->uint16);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_UINT32: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->uint32) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIu32, d->uint32);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_UINT32_HEX: {
                _cleanup_free_ char *p = NULL;

                p = new(char, 8 + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIx32, d->uint32);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_UINT64: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->uint64) + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIu64, d->uint64);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_UINT64_HEX: {
                _cleanup_free_ char *p = NULL;

                p = new(char, 16 + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%" PRIx64, d->uint64);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_PERCENT: {
                _cleanup_free_ char *p = NULL;

                p = new(char, DECIMAL_STR_WIDTH(d->percent) + 2);
                if (!p)
                        return NULL;

                sprintf(p, "%i%%" , d->percent);
                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_IFINDEX: {
                _cleanup_free_ char *p = NULL;

                if (format_ifname_full_alloc(d->ifindex, FORMAT_IFNAME_IFINDEX, &p) < 0)
                        return NULL;

                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_IN_ADDR:
        case TABLE_IN6_ADDR: {
                _cleanup_free_ char *p = NULL;

                if (in_addr_to_string(d->type == TABLE_IN_ADDR ? AF_INET : AF_INET6,
                                      &d->address, &p) < 0)
                        return NULL;

                d->formatted = TAKE_PTR(p);
                break;
        }

        case TABLE_ID128: {
                char *p;

                p = new(char, SD_ID128_STRING_MAX);
                if (!p)
                        return NULL;

                d->formatted = sd_id128_to_string(d->id128, p);
                break;
        }

        case TABLE_UUID: {
                char *p;

                p = new(char, SD_ID128_UUID_STRING_MAX);
                if (!p)
                        return NULL;

                d->formatted = sd_id128_to_uuid_string(d->id128, p);
                break;
        }

        case TABLE_UID: {
                char *p;

                if (!uid_is_valid(d->uid))
                        return table_ersatz_string(t);

                p = new(char, DECIMAL_STR_WIDTH(d->uid) + 1);
                if (!p)
                        return NULL;
                sprintf(p, UID_FMT, d->uid);

                d->formatted = p;
                break;
        }

        case TABLE_GID: {
                char *p;

                if (!gid_is_valid(d->gid))
                        return table_ersatz_string(t);

                p = new(char, DECIMAL_STR_WIDTH(d->gid) + 1);
                if (!p)
                        return NULL;
                sprintf(p, GID_FMT, d->gid);

                d->formatted = p;
                break;
        }

        case TABLE_PID: {
                char *p;

                if (!pid_is_valid(d->pid))
                        return table_ersatz_string(t);

                p = new(char, DECIMAL_STR_WIDTH(d->pid) + 1);
                if (!p)
                        return NULL;
                sprintf(p, PID_FMT, d->pid);

                d->formatted = p;
                break;
        }

        case TABLE_SIGNAL: {
                const char *suffix;
                char *p;

                suffix = signal_to_string(d->int_val);
                if (!suffix)
                        return table_ersatz_string(t);

                p = strjoin("SIG", suffix);
                if (!p)
                        return NULL;

                d->formatted = p;
                break;
        }

        case TABLE_MODE: {
                char *p;

                if (d->mode == MODE_INVALID)
                        return table_ersatz_string(t);

                p = new(char, 4 + 1);
                if (!p)
                        return NULL;

                sprintf(p, "%04o", d->mode & 07777);
                d->formatted = p;
                break;
        }

        case TABLE_MODE_INODE_TYPE:

                if (d->mode == MODE_INVALID)
                        return table_ersatz_string(t);

                return inode_type_to_string(d->mode) ?: table_ersatz_string(t);

        case TABLE_DEVNUM:
                if (devnum_is_zero(d->devnum))
                        return table_ersatz_string(t);

                if (asprintf(&d->formatted, DEVNUM_FORMAT_STR, DEVNUM_FORMAT_VAL(d->devnum)) < 0)
                        return NULL;

                break;

        default:
                assert_not_reached();
        }

        return d->formatted;
}

static int console_width_height(
                const char *s,
                size_t *ret_width,
                size_t *ret_height) {

        size_t max_width = 0, height = 0;
        const char *p;

        assert(s);

        /* Determine the width and height in console character cells the specified string needs. */

        do {
                size_t k;

                p = strchr(s, '\n');
                if (p) {
                        _cleanup_free_ char *c = NULL;

                        c = strndup(s, p - s);
                        if (!c)
                                return -ENOMEM;

                        k = utf8_console_width(c);
                        s = p + 1;
                } else {
                        k = utf8_console_width(s);
                        s = NULL;
                }
                if (k == SIZE_MAX)
                        return -EINVAL;
                if (k > max_width)
                        max_width = k;

                height++;
        } while (!isempty(s));

        if (ret_width)
                *ret_width = max_width;

        if (ret_height)
                *ret_height = height;

        return 0;
}

static int table_data_requested_width_height(
                Table *table,
                TableData *d,
                size_t available_width,
                size_t *ret_width,
                size_t *ret_height,
                bool *have_soft) {

        _cleanup_free_ char *truncated = NULL;
        bool truncation_applied = false;
        size_t width, height;
        const char *t;
        int r;
        bool soft = false;

        t = table_data_format(table, d, false, available_width, &soft);
        if (!t)
                return -ENOMEM;

        if (table->cell_height_max != SIZE_MAX) {
                r = string_truncate_lines(t, table->cell_height_max, &truncated);
                if (r < 0)
                        return r;
                if (r > 0)
                        truncation_applied = true;

                t = truncated;
        }

        r = console_width_height(t, &width, &height);
        if (r < 0)
                return r;

        if (d->maximum_width != SIZE_MAX && width > d->maximum_width)
                width = d->maximum_width;

        if (width < d->minimum_width)
                width = d->minimum_width;

        if (ret_width)
                *ret_width = width;
        if (ret_height)
                *ret_height = height;
        if (have_soft && soft)
                *have_soft = true;

        return truncation_applied;
}

static char *align_string_mem(const char *str, const char *url, size_t new_length, unsigned percent) {
        size_t w = 0, space, lspace, old_length, clickable_length;
        _cleanup_free_ char *clickable = NULL;
        const char *p;
        char *ret;
        int r;

        /* As with ellipsize_mem(), 'old_length' is a byte size while 'new_length' is a width in character cells */

        assert(str);
        assert(percent <= 100);

        old_length = strlen(str);

        if (url) {
                r = terminal_urlify(url, str, &clickable);
                if (r < 0)
                        return NULL;

                clickable_length = strlen(clickable);
        } else
                clickable_length = old_length;

        /* Determine current width on screen */
        p = str;
        while (p < str + old_length) {
                char32_t c;

                if (utf8_encoded_to_unichar(p, &c) < 0) {
                        p++, w++; /* count invalid chars as 1 */
                        continue;
                }

                p = utf8_next_char(p);
                w += unichar_iswide(c) ? 2 : 1;
        }

        /* Already wider than the target, if so, don't do anything */
        if (w >= new_length)
                return clickable ? TAKE_PTR(clickable) : strdup(str);

        /* How much spaces shall we add? An how much on the left side? */
        space = new_length - w;
        lspace = space * percent / 100U;

        ret = new(char, space + clickable_length + 1);
        if (!ret)
                return NULL;

        for (size_t i = 0; i < lspace; i++)
                ret[i] = ' ';
        memcpy(ret + lspace, clickable ?: str, clickable_length);
        for (size_t i = lspace + clickable_length; i < space + clickable_length; i++)
                ret[i] = ' ';

        ret[space + clickable_length] = 0;
        return ret;
}

static bool table_data_isempty(const TableData *d) {
        assert(d);

        if (d->type == TABLE_EMPTY)
                return true;

        /* Let's also consider an empty strv as truly empty. */
        if (IN_SET(d->type, TABLE_STRV, TABLE_STRV_WRAPPED))
                return strv_isempty(d->strv);

        /* Note that an empty string we do not consider empty here! */
        return false;
}

static const char* table_data_color(const TableData *d) {
        assert(d);

        if (d->color)
                return d->color;

        /* Let's implicitly color all "empty" cells in grey, in case an "empty_string" is set that is not empty */
        if (table_data_isempty(d))
                return ansi_grey();

        if (d->type == TABLE_FIELD)
                return ansi_bright_blue();

        return NULL;
}

static const char* table_data_underline(const TableData *d) {
        assert(d);

        if (d->underline)
                return ansi_add_underline_grey();

        if (d->type == TABLE_HEADER)
                return ansi_add_underline();

        return NULL;
}

static const char* table_data_rgap_underline(const TableData *d) {
        assert(d);

        if (d->rgap_underline)
                return ansi_add_underline_grey();

        if (d->type == TABLE_HEADER)
                return ansi_add_underline();

        return NULL;
}

int table_print(Table *t, FILE *f) {
        size_t n_rows, *minimum_width, *maximum_width, display_columns, *requested_width,
                table_minimum_width, table_maximum_width, table_requested_width, table_effective_width,
                *width = NULL;
        _cleanup_free_ size_t *sorted = NULL;
        uint64_t *column_weight, weight_sum;
        int r;

        assert(t);

        if (!f)
                f = stdout;

        /* Ensure we have no incomplete rows */
        assert(t->n_cells % t->n_columns == 0);

        n_rows = t->n_cells / t->n_columns;
        assert(n_rows > 0); /* at least the header row must be complete */

        if (t->sort_map) {
                /* If sorting is requested, let's calculate an index table we use to lookup the actual index to display with. */

                sorted = new(size_t, n_rows);
                if (!sorted)
                        return -ENOMEM;

                for (size_t i = 0; i < n_rows; i++)
                        sorted[i] = i * t->n_columns;

                typesafe_qsort_r(sorted, n_rows, table_data_compare, t);
        }

        if (t->display_map)
                display_columns = t->n_display_map;
        else
                display_columns = t->n_columns;

        assert(display_columns > 0);

        minimum_width = newa(size_t, display_columns);
        maximum_width = newa(size_t, display_columns);
        requested_width = newa(size_t, display_columns);
        column_weight = newa0(uint64_t, display_columns);

        for (size_t j = 0; j < display_columns; j++) {
                minimum_width[j] = 1;
                maximum_width[j] = SIZE_MAX;
        }

        for (unsigned pass = 0; pass < 2; pass++) {
                /* First pass: determine column sizes */

                for (size_t j = 0; j < display_columns; j++)
                        requested_width[j] = SIZE_MAX;

                bool any_soft = false;

                for (size_t i = t->header ? 0 : 1; i < n_rows; i++) {
                        TableData **row;

                        /* Note that we don't care about ordering at this time, as we just want to determine column sizes,
                         * hence we don't care for sorted[] during the first pass. */
                        row = t->data + i * t->n_columns;

                        for (size_t j = 0; j < display_columns; j++) {
                                TableData *d;
                                size_t req_width, req_height;

                                assert_se(d = row[t->display_map ? t->display_map[j] : j]);

                                r = table_data_requested_width_height(t, d,
                                                                      width ? width[j] : SIZE_MAX,
                                                                      &req_width, &req_height, &any_soft);
                                if (r < 0)
                                        return r;
                                if (r > 0) { /* Truncated because too many lines? */
                                        _cleanup_free_ char *last = NULL;
                                        const char *field;

                                        /* If we are going to show only the first few lines of a cell that has
                                         * multiple make sure that we have enough space horizontally to show an
                                         * ellipsis. Hence, let's figure out the last line, and account for its
                                         * length plus ellipsis. */

                                        field = table_data_format(t, d, false,
                                                                  width ? width[j] : SIZE_MAX,
                                                                  &any_soft);
                                        if (!field)
                                                return -ENOMEM;

                                        assert_se(t->cell_height_max > 0);
                                        r = string_extract_line(field, t->cell_height_max-1, &last);
                                        if (r < 0)
                                                return r;

                                        req_width = MAX(req_width,
                                                        utf8_console_width(last) +
                                                        utf8_console_width(special_glyph(SPECIAL_GLYPH_ELLIPSIS)));
                                }

                                /* Determine the biggest width that any cell in this column would like to have */
                                if (requested_width[j] == SIZE_MAX ||
                                    requested_width[j] < req_width)
                                        requested_width[j] = req_width;

                                /* Determine the minimum width any cell in this column needs */
                                if (minimum_width[j] < d->minimum_width)
                                        minimum_width[j] = d->minimum_width;

                                /* Determine the maximum width any cell in this column needs */
                                if (d->maximum_width != SIZE_MAX &&
                                    (maximum_width[j] == SIZE_MAX ||
                                     maximum_width[j] > d->maximum_width))
                                        maximum_width[j] = d->maximum_width;

                                /* Determine the full columns weight */
                                column_weight[j] += d->weight;
                        }
                }

                /* One space between each column */
                table_requested_width = table_minimum_width = table_maximum_width = display_columns - 1;

                /* Calculate the total weight for all columns, plus the minimum, maximum and requested width for the table. */
                weight_sum = 0;
                for (size_t j = 0; j < display_columns; j++) {
                        weight_sum += column_weight[j];

                        table_minimum_width += minimum_width[j];

                        if (maximum_width[j] == SIZE_MAX)
                                table_maximum_width = SIZE_MAX;
                        else
                                table_maximum_width += maximum_width[j];

                        table_requested_width += requested_width[j];
                }

                /* Calculate effective table width */
                if (t->width != 0 && t->width != SIZE_MAX)
                        table_effective_width = t->width;
                else if (t->width == 0 ||
                         ((pass > 0 || !any_soft) && (pager_have() || !isatty_safe(STDOUT_FILENO))))
                        table_effective_width = table_requested_width;
                else
                        table_effective_width = MIN(table_requested_width, columns());

                if (table_maximum_width != SIZE_MAX && table_effective_width > table_maximum_width)
                        table_effective_width = table_maximum_width;

                if (table_effective_width < table_minimum_width)
                        table_effective_width = table_minimum_width;

                if (!width)
                        width = newa(size_t, display_columns);

                if (table_effective_width >= table_requested_width) {
                        size_t extra;

                        /* We have extra room, let's distribute it among columns according to their weights. We first provide
                         * each column with what it asked for and the distribute the rest.  */

                        extra = table_effective_width - table_requested_width;

                        for (size_t j = 0; j < display_columns; j++) {
                                size_t delta;

                                if (weight_sum == 0)
                                        width[j] = requested_width[j] + extra / (display_columns - j); /* Avoid division by zero */
                                else
                                        width[j] = requested_width[j] + (extra * column_weight[j]) / weight_sum;

                                if (maximum_width[j] != SIZE_MAX && width[j] > maximum_width[j])
                                        width[j] = maximum_width[j];

                                if (width[j] < minimum_width[j])
                                        width[j] = minimum_width[j];

                                delta = LESS_BY(width[j], requested_width[j]);

                                /* Subtract what we just added from the rest */
                                if (extra > delta)
                                        extra -= delta;
                                else
                                        extra = 0;

                                assert(weight_sum >= column_weight[j]);
                                weight_sum -= column_weight[j];
                        }

                        break; /* Every column should be happy, no need to repeat calculations. */
                } else {
                        /* We need to compress the table, columns can't get what they asked for. We first provide each column
                         * with the minimum they need, and then distribute anything left. */
                        bool finalize = false;
                        size_t extra;

                        extra = table_effective_width - table_minimum_width;

                        for (size_t j = 0; j < display_columns; j++)
                                width[j] = SIZE_MAX;

                        for (;;) {
                                bool restart = false;

                                for (size_t j = 0; j < display_columns; j++) {
                                        size_t delta, w;

                                        /* Did this column already get something assigned? If so, let's skip to the next */
                                        if (width[j] != SIZE_MAX)
                                                continue;

                                        if (weight_sum == 0)
                                                w = minimum_width[j] + extra / (display_columns - j); /* avoid division by zero */
                                        else
                                                w = minimum_width[j] + (extra * column_weight[j]) / weight_sum;

                                        if (w >= requested_width[j]) {
                                                /* Never give more than requested. If we hit a column like this, there's more
                                                 * space to allocate to other columns which means we need to restart the
                                                 * iteration. However, if we hit a column like this, let's assign it the space
                                                 * it wanted for good early. */

                                                w = requested_width[j];
                                                restart = true;

                                        } else if (!finalize)
                                                continue;

                                        width[j] = w;

                                        assert(w >= minimum_width[j]);
                                        delta = w - minimum_width[j];

                                        assert(delta <= extra);
                                        extra -= delta;

                                        assert(weight_sum >= column_weight[j]);
                                        weight_sum -= column_weight[j];

                                        if (restart && !finalize)
                                                break;
                                }

                                if (finalize)
                                        break;

                                if (!restart)
                                        finalize = true;
                        }

                        if (!any_soft) /* Some columns got less than requested. If some cells were "soft",
                                        * let's try to reformat them with the new widths. Otherwise, let's
                                        * move on. */
                                break;
                }
        }

        /* Second pass: show output */
        for (size_t i = t->header ? 0 : 1; i < n_rows; i++) {
                size_t n_subline = 0;
                bool more_sublines;
                TableData **row;

                if (sorted)
                        row = t->data + sorted[i];
                else
                        row = t->data + i * t->n_columns;

                do {
                        const char *gap_color = NULL, *gap_underline = NULL;
                        more_sublines = false;

                        for (size_t j = 0; j < display_columns; j++) {
                                _cleanup_free_ char *buffer = NULL, *extracted = NULL;
                                bool lines_truncated = false;
                                const char *field, *color = NULL, *underline = NULL;
                                TableData *d;
                                size_t l;

                                assert_se(d = row[t->display_map ? t->display_map[j] : j]);

                                field = table_data_format(t, d, false, width[j], NULL);
                                if (!field)
                                        return -ENOMEM;

                                r = string_extract_line(field, n_subline, &extracted);
                                if (r < 0)
                                        return r;
                                if (r > 0) {
                                        /* There are more lines to come */
                                        if ((t->cell_height_max == SIZE_MAX || n_subline + 1 < t->cell_height_max))
                                                more_sublines = true; /* There are more lines to come */
                                        else
                                                lines_truncated = true;
                                }
                                if (extracted)
                                        field = extracted;

                                l = utf8_console_width(field);
                                if (l > width[j]) {
                                        /* Field is wider than allocated space. Let's ellipsize */

                                        buffer = ellipsize(field, width[j], /* ellipsize at the end if we truncated coming lines, otherwise honour configuration */
                                                           lines_truncated ? 100 : d->ellipsize_percent);
                                        if (!buffer)
                                                return -ENOMEM;

                                        field = buffer;
                                } else {
                                        if (lines_truncated) {
                                                _cleanup_free_ char *padded = NULL;

                                                /* We truncated more lines of this cell, let's add an
                                                 * ellipsis. We first append it, but that might make our
                                                 * string grow above what we have space for, hence ellipsize
                                                 * right after. This will truncate the ellipsis and add a new
                                                 * one. */

                                                padded = strjoin(field, special_glyph(SPECIAL_GLYPH_ELLIPSIS));
                                                if (!padded)
                                                        return -ENOMEM;

                                                buffer = ellipsize(padded, width[j], 100);
                                                if (!buffer)
                                                        return -ENOMEM;

                                                field = buffer;
                                                l = utf8_console_width(field);
                                        }

                                        if (l < width[j]) {
                                                _cleanup_free_ char *aligned = NULL;
                                                /* Field is shorter than allocated space. Let's align with spaces */

                                                aligned = align_string_mem(field, d->url, width[j], d->align_percent);
                                                if (!aligned)
                                                        return -ENOMEM;

                                                /* Drop trailing white spaces of last column when no cosmetics is set. */
                                                if (j == display_columns - 1 &&
                                                    (!colors_enabled() || !table_data_color(d)) &&
                                                    (!underline_enabled() || !table_data_underline(d)) &&
                                                    (!urlify_enabled() || !d->url))
                                                        delete_trailing_chars(aligned, NULL);

                                                free_and_replace(buffer, aligned);
                                                field = buffer;
                                        }
                                }

                                if (l >= width[j] && d->url) {
                                        _cleanup_free_ char *clickable = NULL;

                                        r = terminal_urlify(d->url, field, &clickable);
                                        if (r < 0)
                                                return r;

                                        free_and_replace(buffer, clickable);
                                        field = buffer;
                                }

                                if (colors_enabled() && gap_color)
                                        fputs(gap_color, f);
                                if (underline_enabled() && gap_underline)
                                        fputs(gap_underline, f);

                                if (j > 0)
                                        fputc(' ', f); /* column separator left of cell */

                                /* Undo gap color/underline */
                                if ((colors_enabled() && gap_color) ||
                                    (underline_enabled() && gap_underline))
                                        fputs(ANSI_NORMAL, f);

                                if (colors_enabled()) {
                                        color = table_data_color(d);
                                        if (color)
                                                fputs(color, f);
                                }

                                if (underline_enabled()) {
                                        underline = table_data_underline(d);
                                        if (underline)
                                                fputs(underline, f);
                                }

                                fputs(field, f);

                                if (color || underline)
                                        fputs(ANSI_NORMAL, f);

                                gap_color = d->rgap_color;
                                gap_underline = table_data_rgap_underline(d);
                        }

                        fputc('\n', f);
                        n_subline++;
                } while (more_sublines);
        }

        return fflush_and_check(f);
}

int table_format(Table *t, char **ret) {
        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;
        int r;

        assert(t);
        assert(ret);

        f = memstream_init(&m);
        if (!f)
                return -ENOMEM;

        r = table_print(t, f);
        if (r < 0)
                return r;

        return memstream_finalize(&m, ret, NULL);
}

size_t table_get_rows(Table *t) {
        if (!t)
                return 0;

        assert(t->n_columns > 0);
        return t->n_cells / t->n_columns;
}

size_t table_get_columns(Table *t) {
        if (!t)
                return 0;

        assert(t->n_columns > 0);
        return t->n_columns;
}

size_t table_get_current_column(Table *t) {
        if (!t)
                return 0;

        assert(t->n_columns > 0);
        return t->n_cells % t->n_columns;
}

int table_set_reverse(Table *t, size_t column, bool b) {
        assert(t);
        assert(column < t->n_columns);

        if (!t->reverse_map) {
                if (!b)
                        return 0;

                t->reverse_map = new0(bool, t->n_columns);
                if (!t->reverse_map)
                        return -ENOMEM;
        }

        t->reverse_map[column] = b;
        return 0;
}

TableCell *table_get_cell(Table *t, size_t row, size_t column) {
        size_t i;

        assert(t);

        if (column >= t->n_columns)
                return NULL;

        i = row * t->n_columns + column;
        if (i >= t->n_cells)
                return NULL;

        return TABLE_INDEX_TO_CELL(i);
}

const void *table_get(Table *t, TableCell *cell) {
        TableData *d;

        assert(t);

        d = table_get_data(t, cell);
        if (!d)
                return NULL;

        return d->data;
}

const void* table_get_at(Table *t, size_t row, size_t column) {
        TableCell *cell;

        cell = table_get_cell(t, row, column);
        if (!cell)
                return NULL;

        return table_get(t, cell);
}

static int table_data_to_json(TableData *d, sd_json_variant **ret) {

        switch (d->type) {

        case TABLE_EMPTY:
                return sd_json_variant_new_null(ret);

        case TABLE_STRING:
        case TABLE_PATH:
        case TABLE_PATH_BASENAME:
        case TABLE_FIELD:
        case TABLE_HEADER:
                return sd_json_variant_new_string(ret, d->string);

        case TABLE_STRV:
        case TABLE_STRV_WRAPPED:
                return sd_json_variant_new_array_strv(ret, d->strv);

        case TABLE_BOOLEAN_CHECKMARK:
        case TABLE_BOOLEAN:
                return sd_json_variant_new_boolean(ret, d->boolean);

        case TABLE_TIMESTAMP:
        case TABLE_TIMESTAMP_UTC:
        case TABLE_TIMESTAMP_RELATIVE:
        case TABLE_TIMESTAMP_RELATIVE_MONOTONIC:
        case TABLE_TIMESTAMP_LEFT:
        case TABLE_TIMESTAMP_DATE:
                if (d->timestamp == USEC_INFINITY)
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_unsigned(ret, d->timestamp);

        case TABLE_TIMESPAN:
        case TABLE_TIMESPAN_MSEC:
        case TABLE_TIMESPAN_DAY:
                if (d->timespan == USEC_INFINITY)
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_unsigned(ret, d->timespan);

        case TABLE_SIZE:
        case TABLE_BPS:
                if (d->size == UINT64_MAX)
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_unsigned(ret, d->size);

        case TABLE_INT:
                return sd_json_variant_new_integer(ret, d->int_val);

        case TABLE_INT8:
                return sd_json_variant_new_integer(ret, d->int8);

        case TABLE_INT16:
                return sd_json_variant_new_integer(ret, d->int16);

        case TABLE_INT32:
                return sd_json_variant_new_integer(ret, d->int32);

        case TABLE_INT64:
                return sd_json_variant_new_integer(ret, d->int64);

        case TABLE_UINT:
                return sd_json_variant_new_unsigned(ret, d->uint_val);

        case TABLE_UINT8:
                return sd_json_variant_new_unsigned(ret, d->uint8);

        case TABLE_UINT16:
                return sd_json_variant_new_unsigned(ret, d->uint16);

        case TABLE_UINT32:
        case TABLE_UINT32_HEX:
                return sd_json_variant_new_unsigned(ret, d->uint32);

        case TABLE_UINT64:
        case TABLE_UINT64_HEX:
                return sd_json_variant_new_unsigned(ret, d->uint64);

        case TABLE_PERCENT:
                return sd_json_variant_new_integer(ret, d->percent);

        case TABLE_IFINDEX:
                if (d->ifindex <= 0)
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_integer(ret, d->ifindex);

        case TABLE_IN_ADDR:
                return sd_json_variant_new_array_bytes(ret, &d->address, FAMILY_ADDRESS_SIZE(AF_INET));

        case TABLE_IN6_ADDR:
                return sd_json_variant_new_array_bytes(ret, &d->address, FAMILY_ADDRESS_SIZE(AF_INET6));

        case TABLE_ID128:
                return sd_json_variant_new_id128(ret, d->id128);

        case TABLE_UUID:
                return sd_json_variant_new_uuid(ret, d->id128);

        case TABLE_UID:
                if (!uid_is_valid(d->uid))
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_integer(ret, d->uid);

        case TABLE_GID:
                if (!gid_is_valid(d->gid))
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_integer(ret, d->gid);

        case TABLE_PID:
                if (!pid_is_valid(d->pid))
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_integer(ret, d->pid);

        case TABLE_SIGNAL:
                if (!SIGNAL_VALID(d->int_val))
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_integer(ret, d->int_val);

        case TABLE_MODE:
        case TABLE_MODE_INODE_TYPE:
                if (d->mode == MODE_INVALID)
                        return sd_json_variant_new_null(ret);

                return sd_json_variant_new_unsigned(ret, d->mode);

        case TABLE_DEVNUM:
                if (devnum_is_zero(d->devnum))
                        return sd_json_variant_new_null(ret);

                return sd_json_build(ret, SD_JSON_BUILD_ARRAY(
                                                  SD_JSON_BUILD_UNSIGNED(major(d->devnum)),
                                                  SD_JSON_BUILD_UNSIGNED(minor(d->devnum))));

        default:
                return -EINVAL;
        }
}

char* table_mangle_to_json_field_name(const char *str) {
        /* Tries to make a string more suitable as JSON field name. There are no strict rules defined what a
         * field name can be hence this is a bit vague and black magic. Here's what we do:
         *  - Convert spaces to underscores
         *  - Convert dashes to underscores (some JSON parsers don't like dealing with dashes)
         *  - Convert most other symbols to underscores (for similar reasons)
         *  - Make the first letter of each word lowercase (unless it looks like the whole word is uppercase)
         */

        bool new_word = true;
        char *c;

        assert(str);

        c = strdup(str);
        if (!c)
                return NULL;

        for (char *x = c; *x; x++) {
                if (!strchr(ALPHANUMERICAL, *x)) {
                        *x = '_';
                        new_word = true;
                        continue;
                }

                if (new_word) {
                        if (ascii_tolower(*(x + 1)) == *(x + 1)) /* Heuristic: if next char is upper-case
                                                                  * then we assume the whole word is all-caps
                                                                  * and avoid lowercasing it. */
                                *x = ascii_tolower(*x);
                        new_word = false;
                }
        }

        return c;
}

static int table_make_json_field_name(Table *t, TableData *d, char **ret) {
        _cleanup_free_ char *mangled = NULL;
        const char *n;

        assert(t);
        assert(d);
        assert(ret);

        if (IN_SET(d->type, TABLE_HEADER, TABLE_FIELD))
                n = d->string;
        else {
                n = table_data_format(t, d, /* avoid_uppercasing= */ true, SIZE_MAX, NULL);
                if (!n)
                        return -ENOMEM;
        }

        mangled = table_mangle_to_json_field_name(n);
        if (!mangled)
                return -ENOMEM;

        *ret = TAKE_PTR(mangled);
        return 0;
}

static const char *table_get_json_field_name(Table *t, size_t idx) {
        assert(t);

        return idx < t->n_json_fields ? t->json_fields[idx] : NULL;
}

static int table_to_json_regular(Table *t, sd_json_variant **ret) {
        sd_json_variant **rows = NULL, **elements = NULL;
        _cleanup_free_ size_t *sorted = NULL;
        size_t n_rows, display_columns;
        int r;

        assert(t);
        assert(!t->vertical);

        /* Ensure we have no incomplete rows */
        assert(t->n_columns > 0);
        assert(t->n_cells % t->n_columns == 0);

        n_rows = t->n_cells / t->n_columns;
        assert(n_rows > 0); /* at least the header row must be complete */

        if (t->sort_map) {
                /* If sorting is requested, let's calculate an index table we use to lookup the actual index to display with. */

                sorted = new(size_t, n_rows);
                if (!sorted)
                        return -ENOMEM;

                for (size_t i = 0; i < n_rows; i++)
                        sorted[i] = i * t->n_columns;

                typesafe_qsort_r(sorted, n_rows, table_data_compare, t);
        }

        if (t->display_map)
                display_columns = t->n_display_map;
        else
                display_columns = t->n_columns;
        assert(display_columns > 0);

        elements = new0(sd_json_variant*, display_columns * 2);
        if (!elements)
                return -ENOMEM;

        CLEANUP_ARRAY(elements, (size_t) { display_columns * 2 }, sd_json_variant_unref_many);

        for (size_t j = 0; j < display_columns; j++) {
                _cleanup_free_ char *mangled = NULL;
                const char *n;
                size_t c;

                c = t->display_map ? t->display_map[j] : j;

                /* Use explicitly set JSON field name, if we have one. Otherwise mangle the column field value. */
                n = table_get_json_field_name(t, c);
                if (!n) {
                        r = table_make_json_field_name(t, ASSERT_PTR(t->data[c]), &mangled);
                        if (r < 0)
                                return r;

                        n = mangled;
                }

                r = sd_json_variant_new_string(elements + j*2, n);
                if (r < 0)
                        return r;
        }

        rows = new0(sd_json_variant*, n_rows-1);
        if (!rows)
                return -ENOMEM;

        CLEANUP_ARRAY(rows, (size_t) { n_rows - 1 }, sd_json_variant_unref_many);

        for (size_t i = 1; i < n_rows; i++) {
                TableData **row;

                if (sorted)
                        row = t->data + sorted[i];
                else
                        row = t->data + i * t->n_columns;

                for (size_t j = 0; j < display_columns; j++) {
                        TableData *d;
                        size_t k;

                        assert_se(d = row[t->display_map ? t->display_map[j] : j]);

                        k = j*2+1;
                        elements[k] = sd_json_variant_unref(elements[k]);

                        r = table_data_to_json(d, elements + k);
                        if (r < 0)
                                return r;
                }

                r = sd_json_variant_new_object(rows + i - 1, elements, display_columns * 2);
                if (r < 0)
                        return r;
        }

        return sd_json_variant_new_array(ret, rows, n_rows - 1);
}

static int table_to_json_vertical(Table *t, sd_json_variant **ret) {
        sd_json_variant **elements = NULL;
        size_t n_elements = 0;
        int r;

        assert(t);
        assert(t->vertical);

        if (t->n_columns != 2)
                return -EINVAL;

        /* Ensure we have no incomplete rows */
        assert(t->n_cells % t->n_columns == 0);

        elements = new0(sd_json_variant *, t->n_cells);
        if (!elements)
                return -ENOMEM;

        CLEANUP_ARRAY(elements, n_elements, sd_json_variant_unref_many);

        for (size_t i = t->n_columns; i < t->n_cells; i++) {

                if (i % t->n_columns == 0) {
                        _cleanup_free_ char *mangled = NULL;
                        const char *n;

                        n = table_get_json_field_name(t, i / t->n_columns - 1);
                        if (!n) {
                                r = table_make_json_field_name(t, ASSERT_PTR(t->data[i]), &mangled);
                                if (r < 0)
                                        return r;

                                n = mangled;
                        }

                        r = sd_json_variant_new_string(elements + n_elements, n);
                } else
                        r = table_data_to_json(t->data[i], elements + n_elements);
                if (r < 0)
                        return r;

                n_elements++;
        }

        return sd_json_variant_new_object(ret, elements, n_elements);
}

int table_to_json(Table *t, sd_json_variant **ret) {
        assert(t);

        if (t->vertical)
                return table_to_json_vertical(t, ret);

        return table_to_json_regular(t, ret);
}

int table_print_json(Table *t, FILE *f, sd_json_format_flags_t flags) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(t);

        if (!sd_json_format_enabled(flags)) /* If JSON output is turned off, use regular output */
                return table_print(t, f);

        if (!f)
                f = stdout;

        r = table_to_json(t, &v);
        if (r < 0)
                return r;

        sd_json_variant_dump(v, flags, f, NULL);

        return fflush_and_check(f);
}

int table_print_with_pager(
                Table *t,
                sd_json_format_flags_t json_format_flags,
                PagerFlags pager_flags,
                bool show_header) {

        bool saved_header;
        int r;

        assert(t);

        /* An all-in-one solution for showing tables, and turning on a pager first. Also optionally suppresses
         * the table header and logs about any error. */

        if (json_format_flags & (SD_JSON_FORMAT_OFF|SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                pager_open(pager_flags);

        saved_header = t->header;
        t->header = show_header;
        r = table_print_json(t, stdout, json_format_flags);
        t->header = saved_header;
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

int table_set_json_field_name(Table *t, size_t idx, const char *name) {
        int r;

        assert(t);

        if (name) {
                size_t m;

                m = MAX(idx + 1, t->n_json_fields);
                if (!GREEDY_REALLOC0(t->json_fields, m))
                        return -ENOMEM;

                r = free_and_strdup(t->json_fields + idx, name);
                if (r < 0)
                        return r;

                t->n_json_fields = m;
                return r;
        } else {
                if (idx >= t->n_json_fields)
                        return 0;

                t->json_fields[idx] = mfree(t->json_fields[idx]);
                return 1;
        }
}
