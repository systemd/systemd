static int
do_tur(int fd)
{
        unsigned char turCmdBlk[TUR_CMD_LEN] = { 0x00, 0, 0, 0, 0, 0 };
        struct sg_io_hdr io_hdr;
        unsigned char sense_buffer[32];

        memset(&io_hdr, 0, sizeof (struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof (turCmdBlk);
        io_hdr.mx_sb_len = sizeof (sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_NONE;
        io_hdr.cmdp = turCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.timeout = 20000;
        io_hdr.pack_id = 0;
        if (ioctl(fd, SG_IO, &io_hdr) < 0) {
                close(fd);
                return 0;
        }
        if (io_hdr.info & SG_INFO_OK_MASK) {
                return 0;
        }
        return 1;
}

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
