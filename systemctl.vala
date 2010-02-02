using DBus;
using GLib;

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

        public abstract UnitInfo[] ListUnits() throws DBus.Error;
        public abstract JobInfo[] ListJobs() throws DBus.Error;

        public abstract ObjectPath LoadUnit(string name) throws DBus.Error;
}

static string type = null;
static bool all = false;

public static int job_info_compare(void* key1, void* key2) {
        Manager.JobInfo *j1 = (Manager.JobInfo*) key1;
        Manager.JobInfo *j2 = (Manager.JobInfo*) key2;

        return Posix.strcmp(j1->name, j2->name);
}

public static int unit_info_compare(void* key1, void* key2) {
        Manager.UnitInfo *u1 = (Manager.UnitInfo*) key1;
        Manager.UnitInfo *u2 = (Manager.UnitInfo*) key2;

        int r = Posix.strcmp(Posix.strrchr(u1->id, '.'), Posix.strrchr(u2->id, '.'));
        if (r != 0)
                return r;

        return Posix.strcmp(u1->id, u2->id);
}

static const OptionEntry entries[] = {
        { "type", 't', 0, OptionArg.STRING, out type, "List only particular type of units", "TYPE" },
        { "all",  'a', 0, OptionArg.NONE,   out all,  "Show all units, including dead ones", null  },
        { null }
};

int main (string[] args) {

        OptionContext context = new OptionContext(" -- Control systemd");
        context.add_main_entries(entries, null);

        try {
                context.parse(ref args);
        } catch (GLib.OptionError e) {
                message("Failed to parse command line: %s".printf(e.message));
        }

        try {
                Connection bus = Bus.get(BusType.SESSION);

                Manager manager = bus.get_object (
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1") as Manager;

                if (args[1] == "list-units" || args.length <= 1) {
                        var list = manager.ListUnits();
                        uint n = 0;
                        Posix.qsort(list, list.length, sizeof(Manager.UnitInfo), unit_info_compare);

                        stdout.printf("%-45s %-6s %-12s → %-15s\n\n", "UNIT", "LOAD", "ACTIVE", "JOB");

                        foreach (var i in list) {

                                if (type != null && !i.id.has_suffix(".%s".printf(type)))
                                        continue;

                                if (!all && i.active_state == "inactive")
                                        continue;

                                stdout.printf("%-45s %-6s %-12s", i.id, i.load_state, i.active_state);

                                if (i.job_id != 0)
                                        stdout.printf("→ %-15s", i.job_type);

                                stdout.puts("\n");
                                n++;
                        }

                        if (all)
                                stdout.printf("\n%u units listed.\n", n);
                        else
                                stdout.printf("\n%u live units listed. Pass --all to see dead units, too.\n", n);


                } else if (args[1] == "list-jobs") {
                        var list = manager.ListJobs();
                        Posix.qsort(list, list.length, sizeof(Manager.JobInfo), job_info_compare);

                        foreach (var i in list)
                                stdout.printf("%-45s → %-15s %-7s\n", i.name, i.type, i.state);

                } else if (args[1] == "load") {

                        if (args.length < 3) {
                                stderr.printf("Missing argument.\n");
                                return 1;
                        }

                        manager.LoadUnit(args[2]);
                } else {
                        stderr.printf("Unknown command %s.\n", args[1]);
                        return 1;
                }

        } catch (DBus.Error e) {
                stderr.printf("%s\n".printf(e.message));
        }

        return 0;
}
