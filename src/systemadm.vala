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

using Gtk;
using GLib;
using Pango;

static bool user = false;

public string format_time(uint64 time_ns) {
        if (time_ns <= 0)
                return "";
        Time timestamp = Time.local((time_t) (time_ns / 1000000));
        return timestamp.format("%a, %d %b %Y %H:%M:%S");
}

public void new_column(TreeView view, int column_id, string title) {
        TreeViewColumn col;
        col = new TreeViewColumn.with_attributes(title, new CellRendererText(), "text", column_id);
        col.set_sort_column_id(column_id);
        view.insert_column(col, -1);
}

public class LeftLabel : Label {
        public LeftLabel(string? text = null) {
                if (text != null)
                        set_markup("<b>%s</b>".printf(text));
                halign = Align.START;
                valign = Align.START;
        }
}

public class RightLabel : Label {

        public RightLabel(string? text = null) {
                set_selectable(true);
                set_text_or_na(text);
                wrap = true;
                wrap_mode = Pango.WrapMode.WORD_CHAR;
                halign = Align.START;
                valign = Align.START;
                hexpand = true;
        }

        public void set_text_or_na(string? text = null) {
                if (text == null || text == "")
                        set_markup("<i>n/a</i>");
                else
                        set_text(text);
        }

        public void set_markup_or_na(string? text = null) {
                if (text == null || text == "")
                        set_markup("<i>n/a</i>");
                else
                        set_markup(text);
        }
}

public ScrolledWindow new_scrolled_window(Widget widget) {
       ScrolledWindow scroll = new ScrolledWindow(null, null);
       scroll.set_policy(PolicyType.AUTOMATIC, PolicyType.AUTOMATIC);
       scroll.set_shadow_type(ShadowType.IN);
       scroll.add(widget);
       return scroll;
}

public class MainWindow : Window {

        private string? current_unit_id;
        private uint32 current_job_id;

        private TreeView unit_view;
        private TreeView job_view;

        private ListStore unit_model;
        private ListStore job_model;

        private Gee.HashMap<string, Unit> unit_map;

        private Button start_button;
        private Button stop_button;
        private Button restart_button;
        private Button reload_button;
        private Button cancel_button;

        private Entry unit_load_entry;
        private Button unit_load_button;

        private Button server_snapshot_button;
        private Button server_reload_button;

        private Manager manager;

        private RightLabel unit_id_label;
        private RightLabel unit_dependency_label;
        private RightLabel unit_description_label;
        private RightLabel unit_load_state_label;
        private RightLabel unit_active_state_label;
        private RightLabel unit_sub_state_label;
        private RightLabel unit_fragment_path_label;
        private RightLabel unit_active_enter_timestamp_label;
        private RightLabel unit_active_exit_timestamp_label;
        private RightLabel unit_can_start_label;
        private RightLabel unit_can_reload_label;
        private RightLabel unit_cgroup_label;

        private RightLabel job_id_label;
        private RightLabel job_state_label;
        private RightLabel job_type_label;

        private ComboBoxText unit_type_combo_box;
        private CheckButton inactive_checkbox;

        public MainWindow() throws IOError {
                title = user ? "systemd User Service Manager" : "systemd System Manager";
                set_position(WindowPosition.CENTER);
                set_default_size(1000, 700);
                set_border_width(12);
                destroy.connect(Gtk.main_quit);

                Notebook notebook = new Notebook();
                add(notebook);

                Box unit_vbox = new Box(Orientation.VERTICAL, 12);
                notebook.append_page(unit_vbox, new Label("Units"));
                unit_vbox.set_border_width(12);

                Box job_vbox = new Box(Orientation.VERTICAL, 12);
                notebook.append_page(job_vbox, new Label("Jobs"));
                job_vbox.set_border_width(12);

                unit_type_combo_box = new ComboBoxText();
                Box type_hbox = new Box(Orientation.HORIZONTAL, 6);
                type_hbox.pack_start(unit_type_combo_box, false, false, 0);
                unit_vbox.pack_start(type_hbox, false, false, 0);

                unit_type_combo_box.append_text("All unit types");
                unit_type_combo_box.append_text("Targets");
                unit_type_combo_box.append_text("Slices");
                unit_type_combo_box.append_text("Scopes");
                unit_type_combo_box.append_text("Services");
                unit_type_combo_box.append_text("Devices");
                unit_type_combo_box.append_text("Mounts");
                unit_type_combo_box.append_text("Automounts");
                unit_type_combo_box.append_text("Swaps");
                unit_type_combo_box.append_text("Sockets");
                unit_type_combo_box.append_text("Paths");
                unit_type_combo_box.append_text("Timers");
                unit_type_combo_box.append_text("Snapshots"); // adjust index in server_on_snapshot
                unit_type_combo_box.set_active(0); // Show All
                unit_type_combo_box.changed.connect(unit_type_changed);

                inactive_checkbox = new CheckButton.with_label("inactive too");
                inactive_checkbox.toggled.connect(unit_type_changed);
                type_hbox.pack_start(inactive_checkbox, false, false, 0);

                unit_load_entry = new Entry();
                unit_load_button = new Button.with_mnemonic("_Load");
                unit_load_button.set_sensitive(false);

                unit_load_entry.changed.connect(on_unit_load_entry_changed);
                unit_load_entry.activate.connect(on_unit_load);
                unit_load_button.clicked.connect(on_unit_load);

                Box unit_load_hbox = new Box(Orientation.HORIZONTAL, 6);
                unit_load_hbox.pack_start(unit_load_entry, false, true, 0);
                unit_load_hbox.pack_start(unit_load_button, false, true, 0);

                server_snapshot_button = new Button.with_mnemonic("Take S_napshot");
                server_reload_button = new Button.with_mnemonic("Reload _Configuration");

                server_snapshot_button.clicked.connect(on_server_snapshot);
                server_reload_button.clicked.connect(on_server_reload);

                type_hbox.pack_end(server_snapshot_button, false, true, 0);
                type_hbox.pack_end(server_reload_button, false, true, 0);
                type_hbox.pack_end(unit_load_hbox, false, true, 24);

                unit_model = new ListStore(7, typeof(string), typeof(string), typeof(string), typeof(string), typeof(string), typeof(string), typeof(Unit));
                job_model = new ListStore(6, typeof(string), typeof(string), typeof(string), typeof(string), typeof(Job), typeof(uint32));

                unit_map = new Gee.HashMap<string, Unit>();

                TreeModelFilter unit_model_filter;
                unit_model_filter = new TreeModelFilter(unit_model, null);
                unit_model_filter.set_visible_func(unit_filter);

                TreeModelSort unit_model_sort = new TreeModelSort.with_model(unit_model_filter);

                unit_view = new TreeView.with_model(unit_model_sort);
                job_view = new TreeView.with_model(job_model);

                unit_view.cursor_changed.connect(unit_changed);
                job_view.cursor_changed.connect(job_changed);

                new_column(unit_view, 2, "Load State");
                new_column(unit_view, 3, "Active State");
                new_column(unit_view, 4, "Unit State");
                new_column(unit_view, 0, "Unit");
                new_column(unit_view, 5, "Job");

                new_column(job_view, 0, "Job");
                new_column(job_view, 1, "Unit");
                new_column(job_view, 2, "Type");
                new_column(job_view, 3, "State");

                Paned paned = new Paned(Orientation.VERTICAL);
                unit_vbox.pack_start(paned, true, true, 0);

                paned.pack1(new_scrolled_window(unit_view), true, true);

                Box unit_vbox2 = new Box(Orientation.VERTICAL, 12);
                paned.pack2(new_scrolled_window(unit_vbox2), false, true);

                paned = new Paned(Orientation.VERTICAL);
                job_vbox.pack_start(paned, true, true, 0);

                paned.pack1(new_scrolled_window(job_view), true, true);

                Box job_vbox2 = new Box(Orientation.VERTICAL, 12);
                paned.pack2(new_scrolled_window(job_vbox2), false, true);

                unit_id_label = new RightLabel();
                unit_dependency_label = new RightLabel();
                unit_description_label = new RightLabel();
                unit_load_state_label = new RightLabel();
                unit_active_state_label = new RightLabel();
                unit_sub_state_label = new RightLabel();
                unit_fragment_path_label = new RightLabel();
                unit_active_enter_timestamp_label = new RightLabel();
                unit_active_exit_timestamp_label = new RightLabel();
                unit_can_start_label = new RightLabel();
                unit_can_reload_label = new RightLabel();
                unit_cgroup_label = new RightLabel();

                job_id_label = new RightLabel();
                job_state_label = new RightLabel();
                job_type_label = new RightLabel();

                unit_dependency_label.set_track_visited_links(false);
                unit_dependency_label.set_selectable(true);
                unit_dependency_label.activate_link.connect(on_activate_link);

                unit_fragment_path_label.set_track_visited_links(false);

                Grid unit_grid = new Grid();
                unit_grid.column_spacing = 6;
                unit_grid.row_spacing = 6;
                unit_vbox2.pack_start(unit_grid, false, true, 0);

                Grid job_grid = new Grid();
                job_grid.column_spacing = 6;
                job_grid.column_spacing = 6;
                job_vbox2.pack_start(job_grid, false, true, 0);

                unit_grid.attach(new LeftLabel("Id:"),                     0, 0, 1, 1);
                unit_grid.attach(unit_id_label,                            1, 0, 5, 1);
                unit_grid.attach(new LeftLabel("Description:"),            0, 1, 1, 1);
                unit_grid.attach(unit_description_label,                   1, 1, 5, 1);
                unit_grid.attach(new LeftLabel("Dependencies:"),           0, 2, 1, 1);
                unit_grid.attach(unit_dependency_label,                    1, 2, 5, 1);
                unit_grid.attach(new LeftLabel("Fragment Path:"),          0, 3, 1, 1);
                unit_grid.attach(unit_fragment_path_label,                 1, 3, 5, 1);
                unit_grid.attach(new LeftLabel("Control Group:"),          0, 4, 1, 1);
                unit_grid.attach(unit_cgroup_label,                        1, 4, 5, 1);
                unit_grid.attach(new LeftLabel("Load State:"),             0, 5, 1, 1);
                unit_grid.attach(unit_load_state_label,                    1, 5, 5, 1);

                unit_grid.attach(new LeftLabel("Active State:"),           0, 6, 1, 1);
                unit_grid.attach(unit_active_state_label,                  1, 6, 1, 1);
                unit_grid.attach(new LeftLabel("Unit State:"),             0, 7, 1, 1);
                unit_grid.attach(unit_sub_state_label,                     1, 7, 1, 1);

                unit_grid.attach(new LeftLabel("Activated:"),              2, 6, 1, 1);
                unit_grid.attach(unit_active_enter_timestamp_label,        3, 6, 1, 1);
                unit_grid.attach(new LeftLabel("Deactivated:"),            2, 7, 1, 1);
                unit_grid.attach(unit_active_exit_timestamp_label,         3, 7, 1, 1);

                unit_grid.attach(new LeftLabel("Can Start/Stop:"),         4, 6, 1, 1);
                unit_grid.attach(unit_can_start_label,                     5, 6, 1, 1);
                unit_grid.attach(new LeftLabel("Can Reload:"),             4, 7, 1, 1);
                unit_grid.attach(unit_can_reload_label,                    5, 7, 1, 1);

                job_grid.attach(new LeftLabel("Id:"),                      0, 1, 1, 1);
                job_grid.attach(job_id_label,                              1, 1, 1, 1);
                job_grid.attach(new LeftLabel("State:"),                   0, 2, 1, 1);
                job_grid.attach(job_state_label,                           1, 2, 1, 1);
                job_grid.attach(new LeftLabel("Type:"),                    0, 3, 1, 1);
                job_grid.attach(job_type_label,                            1, 3, 1, 1);

                ButtonBox bbox = new ButtonBox(Orientation.HORIZONTAL);
                bbox.set_layout(ButtonBoxStyle.START);
                bbox.set_spacing(6);
                unit_vbox2.pack_start(bbox, false, true, 0);

                start_button = new Button.with_mnemonic("_Start");
                stop_button = new Button.with_mnemonic("Sto_p");
                reload_button = new Button.with_mnemonic("_Reload");
                restart_button = new Button.with_mnemonic("Res_tart");

                start_button.clicked.connect(on_start);
                stop_button.clicked.connect(on_stop);
                reload_button.clicked.connect(on_reload);
                restart_button.clicked.connect(on_restart);

                bbox.pack_start(start_button, false, true, 0);
                bbox.pack_start(stop_button, false, true, 0);
                bbox.pack_start(restart_button, false, true, 0);
                bbox.pack_start(reload_button, false, true, 0);

                bbox = new ButtonBox(Orientation.HORIZONTAL);
                bbox.set_layout(ButtonBoxStyle.START);
                bbox.set_spacing(6);
                job_vbox2.pack_start(bbox, false, true, 0);

                cancel_button = new Button.with_mnemonic("_Cancel");

                cancel_button.clicked.connect(on_cancel);

                bbox.pack_start(cancel_button, false, true, 0);

                manager = Bus.get_proxy_sync(
                                user ? BusType.SESSION : BusType.SYSTEM,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1");

                manager.unit_new.connect(on_unit_new);
                manager.job_new.connect(on_job_new);
                manager.unit_removed.connect(on_unit_removed);
                manager.job_removed.connect(on_job_removed);

                manager.subscribe();

                clear_unit();
                clear_job();
                populate_unit_model();
                populate_job_model();
        }

        public void populate_unit_model() throws IOError {
                unit_model.clear();

                var list = manager.list_units();

                foreach (var i in list) {
                        TreeIter iter;

                        Properties p = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        i.unit_path);

                        p.properties_changed.connect(on_unit_changed);

                        Unit u = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        i.unit_path);

                        unit_map[i.id] = u;

                        unit_model.append(out iter);
                        unit_model.set(iter,
                                       0, i.id,
                                       1, i.description,
                                       2, i.load_state,
                                       3, i.active_state,
                                       4, i.sub_state,
                                       5, i.job_type != "" ? "→ %s".printf(i.job_type) : "",
                                       6, u);
                }
        }

        public void populate_job_model() throws IOError {
                job_model.clear();

                var list = manager.list_jobs();

                foreach (var i in list) {
                        TreeIter iter;

                        Properties p = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        i.job_path);

                        p.properties_changed.connect(on_job_changed);

                        Job j = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        i.job_path);

                        job_model.append(out iter);
                        job_model.set(iter,
                                      0, "%u".printf(i.id),
                                      1, i.name,
                                      2, "→ %s".printf(i.type),
                                      3, i.state,
                                      4, j,
                                      5, i.id);
                }
        }

        public Unit? get_current_unit() {
                TreePath p;
                unit_view.get_cursor(out p, null);

                if (p == null)
                        return null;

                TreeModel model = unit_view.get_model();
                TreeIter iter;
                Unit u;

                model.get_iter(out iter, p);
                model.get(iter, 6, out u);

                return u;
        }

        public Unit? get_unit(string id) {
                return this.unit_map[id];
        }

        public void unit_changed() {
                Unit u = get_current_unit();

                if (u == null)
                        clear_unit();
                else
                        show_unit(u);
        }

        public void clear_unit() {
                current_unit_id = null;

                start_button.set_sensitive(false);
                stop_button.set_sensitive(false);
                reload_button.set_sensitive(false);
                restart_button.set_sensitive(false);

                unit_id_label.set_text_or_na();
                unit_description_label.set_text_or_na();
                unit_description_label.set_text_or_na();
                unit_load_state_label.set_text_or_na();
                unit_active_state_label.set_text_or_na();
                unit_sub_state_label.set_text_or_na();
                unit_fragment_path_label.set_text_or_na();
                unit_active_enter_timestamp_label.set_text_or_na();
                unit_active_exit_timestamp_label.set_text_or_na();
                unit_can_reload_label.set_text_or_na();
                unit_can_start_label.set_text_or_na();
                unit_cgroup_label.set_text_or_na();
        }

        public string format_unit_link(string i, bool link) {
                Unit? u = get_unit(i);
                if(u == null)
                        return "<span color='grey'>" + i + "</span";

                string color;
                switch (u.sub_state) {
                case "active": color = "blue"; break;
                case "dead": color = "black"; break;
                case "running": color = "green"; break;
                case "plugged": color = "light blue"; break;
                case "mounted": color = "light green"; break;
                case "exited": color = "brown"; break;
                case "failed": color = "red"; break;
                default: color = "black"; break;
                }
                string span = "<span underline='none' color='" + color + "'>"
                              + i + "(" +
                              u.sub_state + ")" + "</span>";
                if(link)
                        return  " <a href='" + i + "'>" + span + "</a>";
                else
                        return span;
        }


        public string make_dependency_string(string? prefix, string word, string[] dependencies) {
                Gee.Collection<unowned string> sorted = new Gee.TreeSet<string>();
                foreach (string i in dependencies)
                        sorted.add(i);

                bool first = true;
                string r;

                if (prefix == null)
                        r = "";
                else
                        r = prefix;

                foreach (string i in sorted) {
                        if (r != "")
                                r += first ? "\n" : ",";

                        if (first) {
                                r += "<b>" + word + ":</b>";
                                first = false;
                        }

                        r += format_unit_link(i, true);
                }

                return r;
        }

        public void show_unit(Unit unit) {
                current_unit_id = unit.id;

                string id_display = format_unit_link(current_unit_id, false);
                bool has_alias = false;
                foreach (string i in unit.names) {
                        if (i == current_unit_id)
                                continue;

                        if (!has_alias) {
                                id_display += " (aliases:";
                                has_alias = true;
                        }

                        id_display += " " + i;
                }
                if(has_alias)
                        id_display += ")";

                unit_id_label.set_markup_or_na(id_display);

                string[]
                        requires = unit.requires,
                        requires_overridable = unit.requires_overridable,
                        requisite = unit.requisite,
                        requisite_overridable = unit.requisite_overridable,
                        wants = unit.wants,
                        required_by = unit.required_by,
                        required_by_overridable = unit.required_by_overridable,
                        wanted_by = unit.wanted_by,
                        conflicts = unit.conflicts,
                        before = unit.before,
                        after = unit.after;

                unit_dependency_label.set_markup_or_na(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(
                                make_dependency_string(null,
                                "requires", requires),
                                "overridable requires", requires_overridable),
                                "requisite", requisite),
                                "overridable requisite", requisite_overridable),
                                "wants", wants),
                                "conflicts", conflicts),
                                "required by", required_by),
                                "overridable required by", required_by_overridable),
                                "wanted by", wanted_by),
                                "after", after),
                                "before", before));

                unit_description_label.set_text_or_na(unit.description);
                unit_load_state_label.set_text_or_na(unit.load_state);
                unit_active_state_label.set_text_or_na(unit.active_state);
                unit_sub_state_label.set_text_or_na(unit.sub_state);

                string fp = unit.fragment_path;
                if (fp != "")
                        unit_fragment_path_label.set_markup_or_na(
                                "<a href=\"file://" + fp +"\">" +
                                "<span underline='none' color='black'>" + fp + "</span></a>");
                else
                        unit_fragment_path_label.set_text_or_na();


                unit_active_enter_timestamp_label.set_text_or_na(format_time(unit.active_enter_timestamp));

                unit_active_exit_timestamp_label.set_text_or_na(format_time(unit.active_exit_timestamp));

                bool b = unit.can_start;
                start_button.set_sensitive(b);
                stop_button.set_sensitive(b);
                restart_button.set_sensitive(b);
                unit_can_start_label.set_text_or_na(b ? "Yes" : "No");

                b = unit.can_reload;
                reload_button.set_sensitive(b);
                unit_can_reload_label.set_text_or_na(b ? "Yes" : "No");

                unit_cgroup_label.set_text_or_na(unit.default_control_group);
        }

        public Job? get_current_job() {
                TreePath p;
                job_view.get_cursor(out p, null);

                if (p == null)
                        return null;

                TreeIter iter;
                TreeModel model = job_view.get_model();
                Job *j;

                model.get_iter(out iter, p);
                model.get(iter, 4, out j);

                return j;
        }

        public void job_changed() {
                Job j = get_current_job();

                if (j == null)
                        clear_job();
                else
                        show_job(j);
        }

        public void clear_job() {
                current_job_id = 0;

                job_id_label.set_text_or_na();
                job_state_label.set_text_or_na();
                job_type_label.set_text_or_na();

                cancel_button.set_sensitive(false);
        }

        public void show_job(Job job) {
                current_job_id = job.id;

                job_id_label.set_text_or_na("%u".printf(current_job_id));
                job_state_label.set_text_or_na(job.state);
                job_type_label.set_text_or_na(job.job_type);

                cancel_button.set_sensitive(true);
        }

        public void on_start() {
                Unit u = get_current_unit();

                if (u == null)
                        return;

                try {
                        u.start("replace");
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_stop() {
                Unit u = get_current_unit();

                if (u == null)
                        return;

                try {
                        u.stop("replace");
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_reload() {
                Unit u = get_current_unit();

                if (u == null)
                        return;

                try {
                        u.reload("replace");
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_restart() {
                Unit u = get_current_unit();

                if (u == null)
                        return;

                try {
                        u.restart("replace");
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_cancel() {
                Job j = get_current_job();

                if (j == null)
                        return;

                try {
                        j.cancel();
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void update_unit_iter(TreeIter iter, string id, Unit u) {

                try  {
                        string t = "";
                        Unit.JobLink jl = u.job;

                        if (jl.id != 0) {
                                Job j = Bus.get_proxy_sync(
                                                user ? BusType.SESSION : BusType.SYSTEM,
                                                "org.freedesktop.systemd1",
                                                jl.path);

                                t = j.job_type;
                        }

                        unit_model.set(iter,
                                       0, id,
                                       1, u.description,
                                       2, u.load_state,
                                       3, u.active_state,
                                       4, u.sub_state,
                                       5, t != "" ? "→ %s".printf(t) : "",
                                       6, u);
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_unit_new(string id, ObjectPath path) {
                try {

                        Properties p = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        path);

                        p.properties_changed.connect(on_unit_changed);

                        TreeIter iter;
                        unit_model.append(out iter);

                        Unit u = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        path);

                        unit_map[id] = u;

                        update_unit_iter(iter, id, u);
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void update_job_iter(TreeIter iter, uint32 id, Job j) {
                job_model.set(iter,
                              0, "%u".printf(id),
                              1, j.unit.id,
                              2, "→ %s".printf(j.job_type),
                              3, j.state,
                              4, j,
                              5, id);
        }

        public void on_job_new(uint32 id, ObjectPath path) {

                try  {

                        Properties p = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        path);

                        p.properties_changed.connect(on_job_changed);

                        TreeIter iter;
                        job_model.append(out iter);

                        Job j = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        path);

                        update_job_iter(iter, id, j);

                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_unit_removed(string id, ObjectPath path) {
                TreeIter iter;
                if (!(unit_model.get_iter_first(out iter)))
                        return;

                do {
                        string name;

                        unit_model.get(iter, 0, out name);

                        if (id == name) {
                                if (current_unit_id == name)
                                        clear_unit();

                                unit_model.remove(iter);
                                break;
                        }

                } while (unit_model.iter_next(ref iter));

                unit_map.unset(id);
        }

        public void on_job_removed(uint32 id, ObjectPath path, string res) {
                TreeIter iter;
                if (!(job_model.get_iter_first(out iter)))
                        return;

                do {
                        uint32 j;

                        job_model.get(iter, 5, out j);

                        if (id == j) {
                                if (current_job_id == j)
                                        clear_job();

                                job_model.remove(iter);

                                break;
                        }

                } while (job_model.iter_next(ref iter));
        }

        public void on_unit_changed(Properties p, string iface, HashTable<string, Value?> changed_properties, string[] invalidated_properties) {

                try {
                        TreeIter iter;
                        string id;

                        Unit u = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        p.get_name(),
                                        p.get_object_path());

                        if (!(unit_model.get_iter_first(out iter)))
                                return;

                        id = u.id;

                        do {
                                string name;

                                unit_model.get(iter, 0, out name);

                                if (id == name) {
                                        update_unit_iter(iter, id, u);

                                        if (current_unit_id == id)
                                                show_unit(u);

                                        break;
                                }

                        } while (unit_model.iter_next(ref iter));

                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_job_changed(Properties p, string iface, HashTable<string, Value?> changed_properties, string[] invalidated_properties) {
                try {
                        TreeIter iter;
                        uint32 id;

                        Job j = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        p.get_name(),
                                        p.get_object_path());

                        if (!(job_model.get_iter_first(out iter)))
                                return;

                        id = j.id;

                        do {
                                uint32 k;

                                job_model.get(iter, 5, out k);

                                if (id == k) {
                                        update_job_iter(iter, id, j);

                                        if (current_job_id == id)
                                                show_job(j);

                                        break;
                                }

                        } while (job_model.iter_next(ref iter));

                } catch (Error e) {
                        show_error(e);
                }
        }

        public bool unit_filter(TreeModel model, TreeIter iter) {
                string id, active_state, job;

                model.get(iter, 0, out id, 3, out active_state, 5, out job);

                if (id == null)
                        return false;

                if (!inactive_checkbox.get_active()
                    && active_state == "inactive" && job == "")
                        return false;

                switch (unit_type_combo_box.get_active()) {
                case 0:
                        return true;
                case 1:
                        return id.has_suffix(".target");
                case 2:
                        return id.has_suffix(".slice");
                case 3:
                        return id.has_suffix(".scope");
                case 4:
                        return id.has_suffix(".service");
                case 5:
                        return id.has_suffix(".device");
                case 6:
                        return id.has_suffix(".mount");
                case 7:
                        return id.has_suffix(".automount");
                case 8:
                        return id.has_suffix(".swap");
                case 9:
                        return id.has_suffix(".socket");
                case 10:
                        return id.has_suffix(".path");
                case 11:
                        return id.has_suffix(".timer");
                case 12:
                        return id.has_suffix(".snapshot");
                default:
                        assert(false);
                        return false;
                }
        }

        public void unit_type_changed() {
                TreeModelFilter model = (TreeModelFilter) ((TreeModelSort) unit_view.get_model()).get_model();

                model.refilter();
        }

        public void on_server_reload() {
                try {
                        manager.reload();
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_server_snapshot() {
                try {
                        manager.create_snapshot();

                        if (unit_type_combo_box.get_active() != 0)
                                unit_type_combo_box.set_active(12);
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_unit_load() {
                string t = unit_load_entry.get_text();

                if (t == "")
                        return;

                try {
                        var path = manager.load_unit(t);

                        Unit u = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        path);

                        var m = new MessageDialog(this,
                                                  DialogFlags.DESTROY_WITH_PARENT,
                                                  MessageType.INFO,
                                                  ButtonsType.CLOSE,
                                                  "Unit available as id %s", u.id);
                        m.title = "Unit";
                        m.run();
                        m.destroy();

                        show_unit(u);
                } catch (Error e) {
                        show_error(e);
                }
        }

        public void on_unit_load_entry_changed() {
                unit_load_button.set_sensitive(unit_load_entry.get_text() != "");
        }

        public bool on_activate_link(string uri) {

                try {
                        string path = manager.get_unit(uri);

                        Unit u = Bus.get_proxy_sync(
                                        user ? BusType.SESSION : BusType.SYSTEM,
                                        "org.freedesktop.systemd1",
                                        path);

                        show_unit(u);
                } catch (Error e) {
                        show_error(e);
                }

                return true;
        }

        public void show_error(Error e) {
				string title, message;
				if (e is DBusError && DBusError.is_remote_error(e)) {
						string remote = DBusError.get_remote_error(e);
						title = "Remote DBus Error: %s".printf(remote);
						message = strerror(dbus_error_to_errno(remote));
				} else {
						title = "Error";
						message = "Error";
				}

                var m = new MessageDialog(this,
                                          DialogFlags.DESTROY_WITH_PARENT,
                                          MessageType.ERROR,
                                          ButtonsType.CLOSE, "%s", message);
				m.title = title;
				m.format_secondary_text("%s", e.message);
                m.run();
                m.destroy();
        }
}

int dbus_error_to_errno(string error) {
		switch (error) {
		case "org.freedesktop.DBus.Error.Failed":
				return Posix.EACCES;
		case "org.freedesktop.DBus.Error.NoMemory":
				return Posix.ENOMEM;
		case "org.freedesktop.DBus.Error.ServiceUnknown":
				return Posix.EHOSTUNREACH;
		case "org.freedesktop.DBus.Error.NameHasNoOwner":
				return Posix.ENXIO;
		case "org.freedesktop.DBus.Error.NoReply":
				return Posix.ETIMEDOUT;
		case "org.freedesktop.DBus.Error.IOError":
				return Posix.EIO;
		case "org.freedesktop.DBus.Error.BadAddress":
				return Posix.EADDRNOTAVAIL;
		case "org.freedesktop.DBus.Error.NotSupported":
				return Posix.ENOTSUP;
		case "org.freedesktop.DBus.Error.LimitsExceeded":
				return Posix.ENOBUFS;
		case "org.freedesktop.DBus.Error.AccessDenied":
				return Posix.EACCES;
		case "org.freedesktop.DBus.Error.AuthFailed":
				return Posix.EACCES;
		case "org.freedesktop.DBus.Error.NoServer":
				/* Errno missing from Posix */
				/* return Posix.EHOSTDOWN; */
				return Posix.EIO;
		case "org.freedesktop.DBus.Error.Timeout":
				return Posix.ETIMEDOUT;
		case "org.freedesktop.DBus.Error.NoNetwork":
				/* Errno missing from Posix */
				/* return Posix.ENONET; */
				return Posix.EIO;
		case "org.freedesktop.DBus.Error.AddressInUse":
				return Posix.EADDRINUSE;
		case "org.freedesktop.DBus.Error.Disconnected":
				return Posix.ECONNRESET;
		case "org.freedesktop.DBus.Error.InvalidArgs":
				return Posix.EINVAL;
		case "org.freedesktop.DBus.Error.FileNotFound":
				return Posix.ENOENT;
		case "org.freedesktop.DBus.Error.FileExists":
				return Posix.EEXIST;
		case "org.freedesktop.DBus.Error.UnknownMethod":
		case "org.freedesktop.DBus.Error.UnknownObject":
		case "org.freedesktop.DBus.Error.UnknownInterface":
		case "org.freedesktop.DBus.Error.UnknownProperty":
				/* Errno missing from Posix */
				/* return Posix.EBADR; */
				return Posix.EIO;
		case "org.freedesktop.DBus.Error.PropertyReadOnly":
				return Posix.EROFS;
		case "org.freedesktop.DBus.Error.UnixProcessIdUnknown":
				return Posix.ESRCH;
		case "org.freedesktop.DBus.Error.InvalidSignature":
				return Posix.EINVAL;
		case "org.freedesktop.DBus.Error.InconsistentMessage":
				return Posix.EBADMSG;
		case "org.freedesktop.DBus.Error.TimedOut":
				return Posix.ETIMEDOUT;
		case "org.freedesktop.DBus.Error.MatchRuleInvalid":
		case "org.freedesktop.DBus.Error.InvalidFileContent":
				return Posix.EINVAL;
		case "org.freedesktop.DBus.Error.MatchRuleNotFound":
				return Posix.ENOENT;
		case "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown":
				return Posix.ESRCH;
		case "org.freedesktop.DBus.Error.ObjectPathInUse":
				return Posix.EBUSY;
		default:
				return Posix.EIO;
		}
}

static const OptionEntry entries[] = {
        { "user",    0,   0,                   OptionArg.NONE, out user, "Connect to user service manager", null },
        { "system",  0,   OptionFlags.REVERSE, OptionArg.NONE, out user, "Connect to system manager",       null },
        { null }
};

void show_error(Error e) {
        var m = new MessageDialog(null, 0, MessageType.ERROR, ButtonsType.CLOSE, "%s", e.message);
        m.run();
        m.destroy();
}

int main(string[] args) {

        try {
                Gtk.init_with_args(ref args, "[OPTION...]", entries, "systemadm");

                MainWindow window = new MainWindow();
                window.show_all();

                Gtk.main();
        } catch (IOError e) {
                show_error(e);
        } catch (GLib.Error e) {
                stderr.printf("%s\n", e.message);
        }

        return 0;
}
