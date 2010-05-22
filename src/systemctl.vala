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
using GLib;

static string type = null;
static bool all = false;
static bool replace = false;
static bool session = false;
static bool block = false;
static Connection? bus = null;
static List<ObjectPath> jobs = null;
static MainLoop main_loop = null;
static int exit_code = 0;

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

public void monitor_on_unit_changed(Unit u) {
        stdout.printf("Unit %s changed.\n", u.id);
}

public void monitor_on_unit_new(string id, ObjectPath path) {
        stdout.printf("Unit %s added.\n", id);

        Unit u = bus.get_object(
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Unit") as Unit;

        u.changed += monitor_on_unit_changed;

        /* FIXME: We leak memory here */
        u.ref();
}

public void monitor_on_job_changed(Job j) {
        stdout.printf("Job %u changed.\n", j.id);
}

public void monitor_on_job_new(uint32 id, ObjectPath path) {
        stdout.printf("Job %u added.\n", id);

        Job j = bus.get_object(
                        "org.freedesktop.systemd1",
                        path,
                        "org.freedesktop.systemd1.Job") as Job;

        j.changed += monitor_on_job_changed;

        /* FIXME: We leak memory here */
        j.ref();
}

public void monitor_on_unit_removed(string id, ObjectPath path) {
        stdout.printf("Unit %s removed.\n", id);
}

public void monitor_on_job_removed(uint32 id, ObjectPath path, bool success) {
        stdout.printf("Job %u removed (success=%i).\n", id, (int) success);
}

public void block_on_job_removed(uint32 id, ObjectPath path, bool success) {

        for (unowned List<ObjectPath> i = jobs; i != null; i = i.next)
                if (i.data == path) {
                        jobs.remove_link(i);
                        break;
                }

        if (jobs == null) {
                if (!success)
                        exit_code = 1;

                main_loop.quit();
        }
}

static const OptionEntry entries[] = {
        { "type",    't', 0,                   OptionArg.STRING, out type,    "List only particular type of units", "TYPE" },
        { "all",     'a', 0,                   OptionArg.NONE,   out all,     "Show all units, including dead ones", null  },
        { "replace", 0,   0,                   OptionArg.NONE,   out replace, "When installing a new job, replace existing conflicting ones", null },
        { "session", 0,   0,                   OptionArg.NONE,   out session, "Connect to session bus", null },
        { "system",  0,   OptionFlags.REVERSE, OptionArg.NONE,   out session, "Connect to system bus", null },
        { "block",   0,   0,                   OptionArg.NONE,   out block,   "Wait until the operation finished", null },
        { null }
};

int main (string[] args) {
        OptionContext context = new OptionContext("[COMMAND [ARGUMENT...]]");
        context.add_main_entries(entries, null);
        context.set_description(
                        "Commands:\n" +
                        "  list-units                      List units\n" +
                        "  list-jobs                       List jobs\n" +
                        "  clear-jobs                      Cancel all jobs\n" +
                        "  load [NAME...]                  Load one or more units\n" +
                        "  cancel [JOB...]                 Cancel one or more jobs\n" +
                        "  start [NAME...]                 Start on or more units\n" +
                        "  stop [NAME...]                  Stop on or more units\n" +
                        "  enter [NAME]                    Start one unit and stop all others\n" +
                        "  restart [NAME...]               Restart on or more units\n" +
                        "  reload [NAME...]                Reload on or more units\n" +
                        "  monitor                         Monitor unit/job changes\n" +
                        "  dump                            Dump server status\n" +
                        "  snapshot [NAME]                 Create a snapshot\n" +
                        "  daemon-reload                   Reload daemon configuration\n" +
                        "  daemon-reexecute                Reexecute daemon\n" +
                        "  show-environment                Dump environment\n" +
                        "  set-environment [NAME=VALUE...] Set one or more environment variables\n" +
                        "  unset-environment [NAME...]     Unset one or more environment variables\n");

        try {
                context.parse(ref args);
        } catch (GLib.OptionError e) {
                message("Failed to parse command line: %s".printf(e.message));
        }

        try {
                bus = Bus.get(session ? BusType.SESSION : BusType.SYSTEM);

                Manager manager = bus.get_object (
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager") as Manager;

                if (args[1] == "list-units" || args.length <= 1) {
                        var list = manager.list_units();
                        uint n = 0;
                        Posix.qsort(list, list.length, sizeof(Manager.UnitInfo), unit_info_compare);

                        stdout.printf("%-45s %-6s %-12s %-12s %-17s\n", "UNIT", "LOAD", "ACTIVE", "SUB", "JOB");

                        foreach (var i in list) {

                                if (type != null && !i.id.has_suffix(".%s".printf(type)))
                                        continue;

                                if (!all && i.active_state == "inactive")
                                        continue;

                                stdout.printf("%-45s %-6s %-12s %-12s", i.id, i.load_state, i.active_state, i.sub_state);

                                if (i.job_id != 0)
                                        stdout.printf(" -> %-15s", i.job_type);

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

                        for (int i = 2; i < args.length; i++)
                                manager.load_unit(args[i]);

                } else if (args[1] == "cancel") {

                        if (args.length < 3) {
                                stderr.printf("Missing argument.\n");
                                return 1;
                        }

                        for (int i = 2; i < args.length; i++) {
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

                        if (block)
                                manager.subscribe();

                        for (int i = 2; i < args.length; i++) {

                                ObjectPath p = manager.load_unit(args[i]);

                                Unit u = bus.get_object(
                                                "org.freedesktop.systemd1",
                                                p,
                                                "org.freedesktop.systemd1.Unit") as Unit;

                                string mode = replace ? "replace" : "fail";

                                ObjectPath j = null;

                                if (args[1] == "start")
                                        j = u.start(mode);
                                else if (args[1] == "stop")
                                        j = u.stop(mode);
                                else if (args[1] == "restart")
                                        j = u.restart(mode);
                                else if (args[1] == "reload")
                                        j = u.reload(mode);

                                if (block)
                                        jobs.append(j);
                        }

                } else if (args[1] == "isolate") {

                        if (args.length != 3) {
                                stderr.printf("Missing argument.\n");
                                return 1;
                        }

                        ObjectPath p = manager.load_unit(args[2]);

                        Unit u = bus.get_object(
                                        "org.freedesktop.systemd1",
                                        p,
                                        "org.freedesktop.systemd1.Unit") as Unit;

                        ObjectPath j = u.start("isolate");

                        if (block) {
                                manager.subscribe();
                                jobs.append(j);
                        }

                } else if (args[1] == "monitor") {

                        manager.subscribe();

                        manager.unit_new += monitor_on_unit_new;
                        manager.unit_removed += monitor_on_unit_removed;
                        manager.job_new += monitor_on_job_new;
                        manager.job_removed += monitor_on_job_removed;

                        main_loop = new MainLoop();
                        main_loop.run();

                } else if (args[1] == "dump")
                        stdout.puts(manager.dump());

                else if (args[1] == "snapshot") {

                        ObjectPath p = manager.create_snapshot(args.length > 2 ? args[2] : "");

                        Unit u = bus.get_object(
                                        "org.freedesktop.systemd1",
                                        p,
                                        "org.freedesktop.systemd1.Unit") as Unit;

                        stdout.printf("%s\n", u.id);

                } else if (args[1] == "daemon-reload")
                        manager.reload();

                else if (args[1] == "daemon-reexecute" || args[1] == "daemon-reexec")
                        manager.reexecute();

                else if (args[1] == "daemon-exit")
                        manager.exit();

                else if (args[1] == "show-environment") {
                        foreach(var x in manager.environment)
                                stderr.printf("%s\n", x);

                } else if (args[1] == "set-environment")
                        manager.set_environment(args[2:args.length]);

                else if (args[1] == "unset-environment")
                        manager.unset_environment(args[2:args.length]);

                else {
                        stderr.printf("Unknown command %s.\n", args[1]);
                        return 1;
                }

                if (jobs != null && block) {
                        manager.job_removed += block_on_job_removed;

                        main_loop = new MainLoop();
                        main_loop.run();
                }

        } catch (DBus.Error e) {
                stderr.printf("%s\n".printf(e.message));
                return 1;
        }

        return exit_code;
}
