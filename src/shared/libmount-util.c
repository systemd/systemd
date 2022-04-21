#include "libmount-util.h"

int libmount_drain(struct libmnt_monitor *monitor) {
        bool rescan = false;
        int r;

        assert(monitor);

        /* Drain all events and verify that the event is valid.
         *
         * Note that libmount also monitors /run/mount mkdir if the directory
         * does not exist yet. The mkdir may generate event which is irrelevant
         * for us.
         *
         * error: r < 0; valid: r == 0, false positive: r == 1 */
        do {
                r = mnt_monitor_next_change(monitor, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to drain libmount events: %m");
                if (r == 0)
                        rescan = true;
        } while (r == 0);

        return rescan;
}

int libmount_parse(const char *path, FILE *source, struct libmnt_table **ret_table,
                   struct libmnt_iter **ret_iter) {

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r;

        /* Older libmount seems to require this. */
        assert(!source || path);

        table = mnt_new_table();
        iter = mnt_new_iter(MNT_ITER_FORWARD);
        if (!table || !iter)
                return -ENOMEM;

        /* If source or path are specified, we use on the functions which ignore utab.
         * Only if both are empty, we use mnt_table_parse_mtab(). */

        if (source)
                r = mnt_table_parse_stream(table, source, path);
        else if (path)
                r = mnt_table_parse_file(table, path);
        else
                r = mnt_table_parse_mtab(table, NULL);
        if (r < 0)
                return r;

        *ret_table = TAKE_PTR(table);
        *ret_iter = TAKE_PTR(iter);
        return 0;
}
