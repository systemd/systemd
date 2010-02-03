using DBus;
using GLib;

static string type = null;
static bool all = false;
static bool replace = false;

public static int job_info_compare(void* key1, void* key2) {
        Manager.JobInfo *j1 = (Manager.JobInfo*) key1;
        Manager.JobInfo *j2 = (Manager.JobInfo*) key2;

        return j1->id < j2->id ? -1 : (j1->id > j2->id ? 1 : 0);
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
        { "type",    't', 0, OptionArg.STRING, out type,    "List only particular type of units", "TYPE" },
        { "all",     'a', 0, OptionArg.NONE,   out all,     "Show all units, including dead ones", null  },
        { "replace", 0,   0, OptionArg.NONE,   out replace, "When installing a new job, replace existing conflicting ones.", null },
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
                        var list = manager.list_units();
                        uint n = 0;
                        Posix.qsort(list, list.length, sizeof(Manager.UnitInfo), unit_info_compare);

                        stdout.printf("%-45s %-6s %-12s %-17s\n", "UNIT", "LOAD", "ACTIVE", "JOB");

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
                        var list = manager.list_jobs();
                        Posix.qsort(list, list.length, sizeof(Manager.JobInfo), job_info_compare);

                        stdout.printf("%4s %-45s %-17s %-7s\n", "JOB", "UNIT", "TYPE", "STATE");

                        foreach (var i in list)
                                stdout.printf("%4u %-45s → %-15s %-7s\n", i.id, i.name, i.type, i.state);

                        stdout.printf("\n%u jobs listed.\n", list.length);

                } else if (args[1] == "clear-jobs") {

                        manager.clear_jobs();

                } else if (args[1] == "load") {

                        if (args.length < 3) {
                                stderr.printf("Missing argument.\n");
                                return 1;
                        }

                        for (uint i = 2; i < args.length; i++)
                                manager.load_unit(args[i]);

                } else if (args[1] == "cancel") {

                        if (args.length < 3) {
                                stderr.printf("Missing argument.\n");
                                return 1;
                        }

                        for (uint i = 2; i < args.length; i++) {
                                uint32 id;

                                if (args[i].scanf("%u", out id) != 1) {
                                        stderr.printf("Failed to parse argument.\n");
                                        return 1;
                                }

                                ObjectPath p = manager.get_job(id);

                                Job j = bus.get_object (
                                                "org.freedesktop.systemd1",
                                                p,
                                                "org.freedesktop.systemd1.Job") as Job;

                                j.cancel();
                        }

                } else if (args[1] == "start" ||
                           args[1] == "stop" ||
                           args[1] == "reload" ||
                           args[1] == "restart") {

                        if (args.length < 3) {
                                stderr.printf("Missing argument.\n");
                                return 1;
                        }

                        for (uint i = 2; i < args.length; i++) {

                                ObjectPath p = manager.get_unit(args[i]);

                                Unit u = bus.get_object(
                                                "org.freedesktop.systemd1",
                                                p,
                                                "org.freedesktop.systemd1.Unit") as Unit;

                                string mode = replace ? "replace" : "fail";

                                if (args[1] == "start")
                                        u.start(mode);
                                else if (args[1] == "stop")
                                        u.stop(mode);
                                else if (args[1] == "restart")
                                        u.restart(mode);
                                else if (args[1] == "reload")
                                        u.reload(mode);
                        }

                } else {
                        stderr.printf("Unknown command %s.\n", args[1]);
                        return 1;
                }

        } catch (DBus.Error e) {
                stderr.printf("%s\n".printf(e.message));
        }

        return 0;
}
