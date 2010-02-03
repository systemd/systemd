using DBus;

[DBus (name = "org.freedesktop.systemd1")]
public interface Manager : DBus.Object {

        public struct UnitInfo {
                string id;
                string description;
                string load_state;
                string active_state;
                ObjectPath unit_path;
                uint32 job_id;
                string job_type;
                ObjectPath job_path;
        }

        public struct JobInfo {
                uint32 id;
                string name;
                string type;
                string state;
                ObjectPath job_path;
                ObjectPath unit_path;
        }

        public abstract UnitInfo[] list_units() throws DBus.Error;
        public abstract JobInfo[] list_jobs() throws DBus.Error;

        public abstract ObjectPath get_unit(string name) throws DBus.Error;
        public abstract ObjectPath load_unit(string name) throws DBus.Error;
        public abstract ObjectPath get_job(uint32 id) throws DBus.Error;

        public abstract void clear_jobs() throws DBus.Error;
}

[DBus (name = "org.freedesktop.systemd1.Unit")]
public interface Unit : DBus.Object {
        public abstract string id { owned get; }
        public abstract string description { owned get; }
        public abstract string load_state { owned get; }
        public abstract string active_state { owned get; }
        public abstract string load_path { owned get; }
        public abstract uint64 active_enter_timestamp { owned get; }
        public abstract uint64 active_exit_timestamp { owned get; }
        public abstract bool can_reload { owned get; }
        public abstract bool can_start { owned get; }

        public abstract ObjectPath start(string mode) throws DBus.Error;
        public abstract ObjectPath stop(string mode) throws DBus.Error;
        public abstract ObjectPath restart(string mode) throws DBus.Error;
        public abstract ObjectPath reload(string mode) throws DBus.Error;
}

[DBus (name = "org.freedesktop.systemd1.Job")]
public interface Job : DBus.Object {
        public abstract uint32 id { owned get; }
        public abstract string state { owned get; }
        public abstract string job_type { owned get; }

        public abstract void cancel() throws DBus.Error;
}
