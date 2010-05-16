/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

using DBus;

[DBus (name = "org.freedesktop.systemd1.Manager")]
public interface Manager : DBus.Object {

        public struct UnitInfo {
                string id;
                string description;
                string load_state;
                string active_state;
                string sub_state;
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

        public abstract string[] environment { owned get; }

        public abstract UnitInfo[] list_units() throws DBus.Error;
        public abstract JobInfo[] list_jobs() throws DBus.Error;

        public abstract ObjectPath get_unit(string name) throws DBus.Error;
        public abstract ObjectPath load_unit(string name) throws DBus.Error;
        public abstract ObjectPath get_job(uint32 id) throws DBus.Error;

        public abstract void clear_jobs() throws DBus.Error;

        public abstract void subscribe() throws DBus.Error;
        public abstract void unsubscribe() throws DBus.Error;

        public abstract string dump() throws DBus.Error;

        public abstract void reload() throws DBus.Error;
        public abstract void reexecute() throws DBus.Error;
        public abstract void exit() throws DBus.Error;

        public abstract ObjectPath create_snapshot(string name = "", bool cleanup = false) throws DBus.Error;

        public abstract void set_environment(string[] names) throws DBus.Error;
        public abstract void unset_environment(string[] names) throws DBus.Error;

        public abstract signal void unit_new(string id, ObjectPath path);
        public abstract signal void unit_removed(string id, ObjectPath path);
        public abstract signal void job_new(uint32 id, ObjectPath path);
        public abstract signal void job_removed(uint32 id, ObjectPath path);
}

[DBus (name = "org.freedesktop.systemd1.Unit")]
public interface Unit : DBus.Object {
        public struct JobLink {
                uint32 id;
                ObjectPath path;
        }

        public abstract string id { owned get; }
        public abstract string[] names { owned get; }
        public abstract string[] requires { owned get; }
        public abstract string[] requires_overridable { owned get; }
        public abstract string[] requisite { owned get; }
        public abstract string[] requisite_overridable { owned get; }
        public abstract string[] wants { owned get; }
        public abstract string[] required_by { owned get; }
        public abstract string[] required_by_overridable { owned get; }
        public abstract string[] wanted_by { owned get; }
        public abstract string[] conflicts { owned get; }
        public abstract string[] before { owned get; }
        public abstract string[] after { owned get; }
        public abstract string description { owned get; }
        public abstract string load_state { owned get; }
        public abstract string active_state { owned get; }
        public abstract string sub_state { owned get; }
        public abstract string fragment_path { owned get; }
        public abstract uint64 inactive_exit_timestamp { owned get; }
        public abstract uint64 active_enter_timestamp { owned get; }
        public abstract uint64 active_exit_timestamp { owned get; }
        public abstract uint64 inactive_enter_timestamp { owned get; }
        public abstract bool can_start { owned get; }
        public abstract bool can_reload { owned get; }
        public abstract JobLink job { owned get; }
        public abstract bool recursive_stop { owned get; }
        public abstract bool stop_when_unneeded { owned get; }
        public abstract string default_control_group { owned get; }
        public abstract string[] control_groups { owned get; }

        public abstract ObjectPath start(string mode) throws DBus.Error;
        public abstract ObjectPath stop(string mode) throws DBus.Error;
        public abstract ObjectPath restart(string mode) throws DBus.Error;
        public abstract ObjectPath reload(string mode) throws DBus.Error;

        public abstract signal void changed();
}

[DBus (name = "org.freedesktop.systemd1.Job")]
public interface Job : DBus.Object {
        public struct UnitLink {
                string id;
                ObjectPath path;
        }

        public abstract uint32 id { owned get; }
        public abstract string state { owned get; }
        public abstract string job_type { owned get; }
        public abstract UnitLink unit { owned get; }

        public abstract void cancel() throws DBus.Error;

        public abstract signal void changed();
}
