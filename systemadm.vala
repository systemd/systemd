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
using DBus;
using Pango;

static bool session = false;

public class LeftLabel : Label {
        public LeftLabel(string? text = null) {
                if (text != null)
                        set_markup("<b>%s</b>".printf(text));
                set_alignment(0, 0);
                set_padding(6, 0);
        }
}

public class RightLabel : Label {
        public RightLabel(string? text = null) {
                set_text_or_na(text);
                set_alignment(0, 0);
                set_ellipsize(EllipsizeMode.START);
                set_selectable(true);
        }

        public void set_text_or_na(string? text = null) {
                if (text == null || text == "")
                        set_markup("<i>n/a</i>");
                else
                        set_text(text);
        }
}

public class MainWindow : Window {

        private string? current_unit_id;
        private uint32 current_job_id;

        private TreeView unit_view;
        private TreeView job_view;

        private ListStore unit_model;
        private ListStore job_model;

        private Button start_button;
        private Button stop_button;
        private Button restart_button;
        private Button reload_button;
        private Button cancel_button;

        private Entry unit_load_entry;
        private Button unit_load_button;

        private Button server_snapshot_button;
        private Button server_reload_button;

        private Connection bus;
        private Manager manager;

        private RightLabel unit_id_label;
        private RightLabel unit_aliases_label;
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

        private ComboBox unit_type_combo_box;

        public MainWindow() throws DBus.Error {
                title = "systemadm";
                position = WindowPosition.CENTER;
                set_default_size(1000, 700);
                set_border_width(12);
                destroy += Gtk.main_quit;

                Notebook notebook = new Notebook();
                add(notebook);

                Box unit_vbox = new VBox(false, 12);
                notebook.append_page(unit_vbox, new Label("Units"));
                unit_vbox.set_border_width(12);

                Box job_vbox = new VBox(false, 12);
                notebook.append_page(job_vbox, new Label("Jobs"));
                job_vbox.set_border_width(12);

                unit_type_combo_box = new ComboBox.text();
                Box type_hbox = new HBox(false, 6);
                type_hbox.pack_start(unit_type_combo_box, false, false, 0);
                unit_vbox.pack_start(type_hbox, false, false, 0);

                unit_type_combo_box.append_text("Show All Units");
                unit_type_combo_box.append_text("Show Only Live Units");
                unit_type_combo_box.append_text("Services");
                unit_type_combo_box.append_text("Sockets");
                unit_type_combo_box.append_text("Devices");
                unit_type_combo_box.append_text("Mounts");
                unit_type_combo_box.append_text("Automounts");
                unit_type_combo_box.append_text("Targets");
                unit_type_combo_box.append_text("Snapshots");
                unit_type_combo_box.set_active(1);
                unit_type_combo_box.changed += unit_type_changed;

                unit_load_entry = new Entry();
                unit_load_button = new Button.with_mnemonic("_Load");
                unit_load_button.set_sensitive(false);

                unit_load_entry.changed += on_unit_load_entry_changed;
                unit_load_entry.activate += on_unit_load;
                unit_load_button.clicked += on_unit_load;

                Box unit_load_hbox = new HBox(false, 6);
                unit_load_hbox.pack_start(unit_load_entry, false, true, 0);
                unit_load_hbox.pack_start(unit_load_button, false, true, 0);

                server_snapshot_button = new Button.with_mnemonic("Take S_napshot");
                server_reload_button = new Button.with_mnemonic("Reload _Configuration");

                server_snapshot_button.clicked += on_server_snapshot;
                server_reload_button.clicked += on_server_reload;

                type_hbox.pack_end(server_snapshot_button, false, true, 0);
                type_hbox.pack_end(server_reload_button, false, true, 0);
                type_hbox.pack_end(unit_load_hbox, false, true, 24);

                unit_model = new ListStore(7, typeof(string), typeof(string), typeof(string), typeof(string), typeof(string), typeof(string), typeof(Unit));
                job_model = new ListStore(6, typeof(string), typeof(string), typeof(string), typeof(string), typeof(Job), typeof(uint32));

                TreeModelFilter unit_model_filter;
                unit_model_filter = new TreeModelFilter(unit_model, null);
                unit_model_filter.set_visible_func(unit_filter);

                unit_view = new TreeView.with_model(unit_model_filter);
                job_view = new TreeView.with_model(job_model);

                unit_view.cursor_changed += unit_changed;
                job_view.cursor_changed += job_changed;

                unit_view.insert_column_with_attributes(-1, "Load State", new CellRendererText(), "text", 2);
                unit_view.insert_column_with_attributes(-1, "Active State", new CellRendererText(), "text", 3);
                unit_view.insert_column_with_attributes(-1, "Unit State", new CellRendererText(), "text", 4);
                unit_view.insert_column_with_attributes(-1, "Unit", new CellRendererText(), "text", 0);
                unit_view.insert_column_with_attributes(-1, "Job", new CellRendererText(), "text", 5);

                job_view.insert_column_with_attributes(-1, "Job", new CellRendererText(), "text", 0);
                job_view.insert_column_with_attributes(-1, "Unit", new CellRendererText(), "text", 1);
                job_view.insert_column_with_attributes(-1, "Type", new CellRendererText(), "text", 2);
                job_view.insert_column_with_attributes(-1, "State", new CellRendererText(), "text", 3);

                ScrolledWindow scroll = new ScrolledWindow(null, null);
                scroll.set_policy(PolicyType.AUTOMATIC, PolicyType.AUTOMATIC);
                scroll.set_shadow_type(ShadowType.IN);
                scroll.add(unit_view);
                unit_vbox.pack_start(scroll, true, true, 0);

                scroll = new ScrolledWindow(null, null);
                scroll.set_policy(PolicyType.AUTOMATIC, PolicyType.AUTOMATIC);
                scroll.set_shadow_type(ShadowType.IN);
                scroll.add(job_view);
                job_vbox.pack_start(scroll, true, true, 0);

                unit_id_label = new RightLabel();
                unit_aliases_label = new RightLabel();
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

                Table unit_table = new Table(8, 6, false);
                unit_table.set_row_spacings(6);
                unit_table.set_border_width(0);
                unit_vbox.pack_start(unit_table, false, true, 0);

                Table job_table = new Table(2, 2, false);
                job_table.set_row_spacings(6);
                job_table.set_border_width(0);
                job_vbox.pack_start(job_table, false, true, 0);

                unit_table.attach(new LeftLabel("Id:"),                     0, 1, 0, 1, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_id_label,                            1, 6, 0, 1, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(new LeftLabel("Aliases:"),                0, 1, 1, 2, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_aliases_label,                       1, 6, 1, 2, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(new LeftLabel("Description:"),            0, 1, 2, 3, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_description_label,                   1, 6, 2, 3, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(new LeftLabel("Fragment Path:"),          0, 1, 3, 4, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_fragment_path_label,                 1, 6, 3, 4, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(new LeftLabel("Control Group:"),          0, 1, 4, 5, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_cgroup_label,                        1, 6, 4, 5, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);

                unit_table.attach(new LeftLabel("Load State:"),             0, 1, 5, 6, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_load_state_label,                    1, 2, 5, 6, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(new LeftLabel("Active State:"),           0, 1, 6, 7, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_active_state_label,                  1, 2, 6, 7, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(new LeftLabel("Unit State:"),             0, 1, 7, 8, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_sub_state_label,                     1, 2, 7, 8, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);

                unit_table.attach(new LeftLabel("Active Enter Timestamp:"), 2, 3, 6, 7, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_active_enter_timestamp_label,        3, 4, 6, 7, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(new LeftLabel("Active Exit Timestamp:"),  2, 3, 7, 8, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_active_exit_timestamp_label,         3, 4, 7, 8, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);

                unit_table.attach(new LeftLabel("Can Start/Stop:"),         4, 5, 6, 7, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_can_start_label,                     5, 6, 6, 7, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(new LeftLabel("Can Reload:"),             4, 5, 7, 8, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                unit_table.attach(unit_can_reload_label,                    5, 6, 7, 8, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);

                job_table.attach(new LeftLabel("Id:"),                      0, 1, 0, 1, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                job_table.attach(job_id_label,                              1, 2, 0, 1, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                job_table.attach(new LeftLabel("State:"),                   0, 1, 1, 2, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                job_table.attach(job_state_label,                           1, 2, 1, 2, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                job_table.attach(new LeftLabel("Type:"),                    0, 1, 2, 3, AttachOptions.FILL, AttachOptions.FILL, 0, 0);
                job_table.attach(job_type_label,                            1, 2, 2, 3, AttachOptions.EXPAND|AttachOptions.FILL, AttachOptions.FILL, 0, 0);

                ButtonBox bbox = new HButtonBox();
                bbox.set_layout(ButtonBoxStyle.START);
                bbox.set_spacing(6);
                unit_vbox.pack_start(bbox, false, true, 0);

                start_button = new Button.with_mnemonic("_Start");
                stop_button = new Button.with_mnemonic("Sto_p");
                reload_button = new Button.with_mnemonic("_Reload");
                restart_button = new Button.with_mnemonic("Res_tart");

                start_button.clicked += on_start;
                stop_button.clicked += on_stop;
                reload_button.clicked += on_reload;
                restart_button.clicked += on_restart;

                bbox.pack_start(start_button, false, true, 0);
                bbox.pack_start(stop_button, false, true, 0);
                bbox.pack_start(restart_button, false, true, 0);
                bbox.pack_start(reload_button, false, true, 0);

                bbox = new HButtonBox();
                bbox.set_layout(ButtonBoxStyle.START);
                bbox.set_spacing(6);
                job_vbox.pack_start(bbox, false, true, 0);

                cancel_button = new Button.with_mnemonic("_Cancel");

                cancel_button.clicked += on_cancel;

                bbox.pack_start(cancel_button, false, true, 0);

                bus = Bus.get(session ? BusType.SESSION : BusType.SYSTEM);

                manager = bus.get_object(
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager") as Manager;

                manager.unit_new += on_unit_new;
                manager.job_new += on_job_new;
                manager.unit_removed += on_unit_removed;
                manager.job_removed += on_job_removed;

                manager.subscribe();

                clear_unit();
                clear_job();
                populate_unit_model();
                populate_job_model();
        }

        public void populate_unit_model() throws DBus.Error {
                unit_model.clear();

                var list = manager.list_units();

                foreach (var i in list) {
                        TreeIter iter;

                        Unit u = bus.get_object(
                                        "org.freedesktop.systemd1",
                                        i.unit_path,
                                        "org.freedesktop.systemd1.Unit") as Unit;

                        u.changed += on_unit_changed;

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

        public void populate_job_model() throws DBus.Error {
                job_model.clear();

                var list = manager.list_jobs();

                foreach (var i in list) {
                        TreeIter iter;

                        Job j = bus.get_object(
                                        "org.freedesktop.systemd1",
                                        i.job_path,
                                        "org.freedesktop.systemd1.Job") as Job;

                        j.changed += on_job_changed;

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
                unit_aliases_label.set_text_or_na();
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

        public void show_unit(Unit unit) {
                current_unit_id = unit.id;

                unit_id_label.set_text_or_na(current_unit_id);

                string a = "";
                foreach (string i in unit.names) {
                        if (i == current_unit_id)
                                continue;

                        if (a == "")
                                a = i;
                        else
                                a += "\n" + i;
                }

                unit_aliases_label.set_text_or_na(a);
                unit_description_label.set_text_or_na(unit.description);
                unit_load_state_label.set_text_or_na(unit.load_state);
                unit_active_state_label.set_text_or_na(unit.active_state);
                unit_sub_state_label.set_text_or_na(unit.sub_state);
                unit_fragment_path_label.set_text_or_na(unit.fragment_path);

                uint64 t = unit.active_enter_timestamp;
                if (t > 0) {
                        Time timestamp = Time.local((time_t) (t / 1000000));
                        unit_active_enter_timestamp_label.set_text_or_na(timestamp.format("%a, %d %b %Y %H:%M:%S %z"));
                } else
                        unit_active_enter_timestamp_label.set_text_or_na();

                t = unit.active_exit_timestamp;
                if (t > 0) {
                        Time timestamp = Time.local((time_t) (t / 1000000));
                        unit_active_exit_timestamp_label.set_text_or_na(timestamp.format("%a, %d %b %Y %H:%M:%S %z"));
                } else
                        unit_active_exit_timestamp_label.set_text_or_na();

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
                } catch (DBus.Error e) {
                        show_error(e.message);
                }
        }

        public void on_stop() {
                Unit u = get_current_unit();

                if (u == null)
                        return;

                try {
                        u.stop("replace");
                } catch (DBus.Error e) {
                        show_error(e.message);
                }
        }

        public void on_reload() {
                Unit u = get_current_unit();

                if (u == null)
                        return;

                try {
                        u.reload("replace");
                } catch (DBus.Error e) {
                        show_error(e.message);
                }
        }

        public void on_restart() {
                Unit u = get_current_unit();

                if (u == null)
                        return;

                try {
                        u.restart("replace");
                } catch (DBus.Error e) {
                        show_error(e.message);
                }
        }

        public void on_cancel() {
                Job j = get_current_job();

                if (j == null)
                        return;

                try {
                        j.cancel();
                } catch (DBus.Error e) {
                        show_error(e.message);
                }
        }

        public void update_unit_iter(TreeIter iter, string id, Unit u) {

                string t = "";
                Unit.JobLink jl = u.job;

                if (jl.id != 0) {
                        Job j = bus.get_object(
                                        "org.freedesktop.systemd1",
                                        jl.path,
                                        "org.freedesktop.systemd1.Job") as Job;

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
        }

        public void on_unit_new(string id, ObjectPath path) {
                Unit u = bus.get_object(
                                "org.freedesktop.systemd1",
                                path,
                                "org.freedesktop.systemd1.Unit") as Unit;

                u.changed += on_unit_changed;

                TreeIter iter;
                unit_model.append(out iter);
                update_unit_iter(iter, id, u);
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
                Job j = bus.get_object(
                                "org.freedesktop.systemd1",
                                path,
                                "org.freedesktop.systemd1.Job") as Job;

                j.changed += on_job_changed;

                TreeIter iter;
                job_model.append(out iter);
                update_job_iter(iter, id, j);
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
        }

        public void on_job_removed(uint32 id, ObjectPath path) {
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

        public void on_unit_changed(Unit u) {
                TreeIter iter;
                string id;

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
        }

        public void on_job_changed(Job j) {
                TreeIter iter;
                uint32 id;

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
        }

        public bool unit_filter(TreeModel model, TreeIter iter) {
                string id, active_state, job;

                model.get(iter, 0, out id, 3, out active_state, 5, out job);

                if (id == null)
                        return false;

                switch (unit_type_combo_box.get_active()) {

                        case 0:
                                return true;

                        case 1:
                                return active_state != "inactive" || job != "";

                        case 2:
                                return id.has_suffix(".service");

                        case 3:
                                return id.has_suffix(".socket");

                        case 4:
                                return id.has_suffix(".device");

                        case 5:
                                return id.has_suffix(".mount");

                        case 6:
                                return id.has_suffix(".automount");

                        case 7:
                                return id.has_suffix(".target");

                        case 8:
                                return id.has_suffix(".snapshot");
                }

                return false;
        }

        public void unit_type_changed() {
                TreeModelFilter model = (TreeModelFilter) unit_view.get_model();

                model.refilter();
        }

        public void on_server_reload() {
                try {
                        manager.reload();
                } catch (DBus.Error e) {
                        show_error(e.message);
                }
        }

        public void on_server_snapshot() {
                try {
                        manager.create_snapshot();

                        if (unit_type_combo_box.get_active() != 0)
                                unit_type_combo_box.set_active(8);

                } catch (DBus.Error e) {
                        show_error(e.message);
                }
        }

        public void on_unit_load() {
                try {
                        var path = manager.load_unit(unit_load_entry.get_text());

                        Unit u = bus.get_object(
                                        "org.freedesktop.systemd1",
                                        path,
                                        "org.freedesktop.systemd1.Unit") as Unit;

                        var m = new MessageDialog(this,
                                                  DialogFlags.DESTROY_WITH_PARENT,
                                                  MessageType.INFO,
                                                  ButtonsType.CLOSE,
                                                  "Unit available as id %s", u.id);
                        m.title = "Unit";
                        m.run();
                        m.destroy();

                } catch (DBus.Error e) {
                        show_error(e.message);
                }
        }

        public void on_unit_load_entry_changed() {
                unit_load_button.set_sensitive(unit_load_entry.get_text() != "");
        }

        public void show_error(string e) {
                var m = new MessageDialog(this,
                                          DialogFlags.DESTROY_WITH_PARENT,
                                          MessageType.ERROR,
                                          ButtonsType.CLOSE, "%s", e);
                m.title = "Error";
                m.run();
                m.destroy();
        }

}

static const OptionEntry entries[] = {
        { "session", 0,   0,                   OptionArg.NONE,   out session, "Connect to session bus", null },
        { "system",  0,   OptionFlags.REVERSE, OptionArg.NONE,   out session, "Connect to system bus", null },
        { null }
};

void show_error(string e) {
        var m = new MessageDialog(null, 0, MessageType.ERROR, ButtonsType.CLOSE, "%s", e);
        m.run();
        m.destroy();
}

int main (string[] args) {

        try {
                Gtk.init_with_args(ref args, "[OPTION...]", entries, "systemadm");

                MainWindow window = new MainWindow();
                window.show_all();

                Gtk.main();
        } catch (DBus.Error e) {
                show_error(e.message);
        } catch (GLib.Error e) {
                show_error(e.message);
        }

        return 0;
}
