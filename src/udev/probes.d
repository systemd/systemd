provider udev {
        probe worker_spawned(const char*, const char*, int); /* (sysname, action, pid) */
        probe kernel_uevent_received(const char*, const char*); /* (sysname, action) */
        probe rules_start(const char*, const char*); /* (sysname, action) */
        probe rules_finished(const char*, const char*);  /* (sysname, action) */
        probe rules_apply_line(const char*, const char*, const char*, unsigned int); /* (sysname, action, filename, line_number) */
        probe spawn_exec(const char*, const char*, const char*); /* (sysname, action, cmd) */
        probe spawn_exit(const char*, const char*, const char*); /* (sysname, action, cmd) */
        probe spawn_timeout(const char *, const char*, const char*) /* (sysname, action, cmd) */
        probe synthetic_change_event(const char*, const char*) /* (sysname, action) */
};
