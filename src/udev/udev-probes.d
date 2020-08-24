provider udev {
        probe worker_spawned(const char* sysname, const char* action, int pid);
        probe kernel_uevent_received(const char* sysname, const char* action);
        probe rules_start(const char* sysname, const char* action);
        probe rules_finished(const char* sysname, const char* action);
        probe rules_apply_line(const char* sysname, const char* action, const char* filename, unsigned int lineno);
        probe spawn_exec(const char* sysname, const char* action, const char* cmd);
        probe spawn_exit(const char* sysname, const char* action, const char* cmd);
        probe spawn_timeout(const char* sysname, const char* action, const char* cmd);
        probe synthetic_change_event(const char* sysname, const char* action);
};
