static int
del_map(char * str) {
        struct dm_task *dmt;

        if (!(dmt = dm_task_create(DM_DEVICE_REMOVE)))
                return 0;
        if (!dm_task_set_name(dmt, str))
                goto delout;
        if (!dm_task_run(dmt))
                goto delout;

        printf("Deleted device map : %s\n", str);

        delout:
        dm_task_destroy(dmt);
        return 1;
}

get_table(const char * str)
{
        int r = 0;
        struct dm_task *dmt;
        void *next = NULL;
        uint64_t start, length;
        char *target_type = NULL;
        char *params;

        if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
                return 0;

        if (!dm_task_set_name(dmt, str))
                goto out;

        if (!dm_task_run(dmt))
                goto out;

        do {
                next = dm_get_next_target(dmt, next, &start, &length,
                                          &target_type, &params);
                if (target_type) {
                        printf("%" PRIu64 " %" PRIu64 " %s %s\n",
                               start, length, target_type, params);
                }
        } while (next);

        r = 1;

      out:
        dm_task_destroy(dmt);
        return r;

}
