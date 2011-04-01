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
using Linux;
using Posix;
using Notify;

[CCode (cheader_filename = "time.h")]
extern int clock_gettime(int id, out timespec ts);

public class PasswordDialog : Dialog {

        public Entry entry;

        public PasswordDialog(string message, string icon) {
                set_title("System Password");
                set_has_separator(false);
                set_border_width(8);
                set_default_response(ResponseType.OK);
                set_icon_name(icon);

#if LIBNOTIFY07
                add_button(Stock.CANCEL, ResponseType.CANCEL);
                add_button(Stock.OK, ResponseType.OK);
#else
                add_button(STOCK_CANCEL, ResponseType.CANCEL);
                add_button(STOCK_OK, ResponseType.OK);
#endif

                Container content = (Container) get_content_area();

                Box hbox = new HBox(false, 16);
                hbox.set_border_width(8);
                content.add(hbox);

                Image image = new Image.from_icon_name(icon, IconSize.DIALOG);
                hbox.pack_start(image, false, false);

                Box vbox = new VBox(false, 8);
                hbox.pack_start(vbox, true, true);

                Label label = new Label(message);
                vbox.pack_start(label, false, false);

                entry = new Entry();
                entry.set_visibility(false);
                entry.set_activates_default(true);
                vbox.pack_start(entry, false, false);

                entry.activate.connect(on_entry_activated);

                show_all();
        }

        public void on_entry_activated() {
                response(ResponseType.OK);
        }
}

public class MyStatusIcon : StatusIcon {

        File directory;
        File current;
        FileMonitor file_monitor;

        string message;
        string icon;
        string socket;

        PasswordDialog password_dialog;

        public MyStatusIcon() throws GLib.Error {
                GLib.Object(icon_name : "dialog-password");
                set_title("System Password Request");

                directory = File.new_for_path("/run/systemd/ask-password/");
                file_monitor = directory.monitor_directory(0);
                file_monitor.changed.connect(file_monitor_changed);

                current = null;
                look_for_password();

                activate.connect(status_icon_activate);
        }

        void file_monitor_changed(GLib.File file, GLib.File? other_file, GLib.FileMonitorEvent event_type) {

                if (!file.get_basename().has_prefix("ask."))
                        return;

                if (event_type == FileMonitorEvent.CREATED ||
                    event_type == FileMonitorEvent.DELETED) {
                        try {
                                look_for_password();
                        } catch (Error e) {
                                show_error(e.message);
                        }
                }
        }

        void look_for_password() throws GLib.Error {

                if (current != null) {
                        if (!current.query_exists()) {
                                current = null;
                                if (password_dialog != null)
                                        password_dialog.response(ResponseType.REJECT);
                        }
                }

                if (current == null) {
                        FileEnumerator enumerator = directory.enumerate_children("standard::name", FileQueryInfoFlags.NOFOLLOW_SYMLINKS);

                        FileInfo i;
                        while ((i = enumerator.next_file()) != null) {
                                if (!i.get_name().has_prefix("ask."))
                                        continue;

                                current = directory.get_child(i.get_name());

                                if (load_password())
                                        break;

                                current = null;
                        }
                }

                if (current == null)
                        set_visible(false);
        }

        bool load_password() throws GLib.Error {

                KeyFile key_file = new KeyFile();

                try {
                        timespec ts;

                        key_file.load_from_file(current.get_path(), KeyFileFlags.NONE);

                        string not_after_as_string = key_file.get_string("Ask", "NotAfter");

                        clock_gettime(1, out ts);
                        uint64 now = (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);

                        uint64 not_after;
                        if (not_after_as_string.scanf("%llu", out not_after) != 1)
                                return false;

                        if (not_after < now)
                                return false;

                        socket = key_file.get_string("Ask", "Socket");
                } catch (GLib.Error e) {
                        return false;
                }

                try {
                        message = key_file.get_string("Ask", "Message").compress();
                } catch (GLib.Error e) {
                        message = "Please Enter System Password!";
                }

                set_tooltip_text(message);

                try {
                        icon = key_file.get_string("Ask", "Icon");
                } catch (GLib.Error e) {
                        icon = "dialog-password";
                }
                set_from_icon_name(icon);

                set_visible(true);

#if LIBNOTIFY07
                Notification n = new Notification(title, message, icon);
#else
                Notification n = new Notification(title, message, icon, null);
                n.attach_to_status_icon(this);
#endif
                n.set_timeout(5000);
                n.show();

                return true;
        }

        void status_icon_activate() {

                if (current == null)
                        return;

                if (password_dialog != null) {
                        password_dialog.present();
                        return;
                }

                password_dialog = new PasswordDialog(message, icon);

                int result = password_dialog.run();
                string password = password_dialog.entry.get_text();

                password_dialog.destroy();
                password_dialog = null;

                if (result == ResponseType.REJECT ||
                    result == ResponseType.DELETE_EVENT)
                        return;

                int to_process;

                try {
                        Process.spawn_async_with_pipes(
                                        null,
                                        { "/usr/bin/pkexec", "/lib/systemd/systemd-reply-password", result == ResponseType.OK ? "1" : "0", socket },
                                        null,
                                        0,
                                        null,
                                        null,
                                        out to_process,
                                        null,
                                        null);

                        OutputStream stream = new UnixOutputStream(to_process, true);
#if VALA_0_12
                        stream.write(password.data, null);
#else
                        stream.write(password, password.length, null);
#endif
                } catch (Error e) {
                        show_error(e.message);
                }
        }
}

static const OptionEntry entries[] = {
        { null }
};

void show_error(string e) {
        var m = new MessageDialog(null, 0, MessageType.ERROR, ButtonsType.CLOSE, "%s", e);
        m.run();
        m.destroy();
}

int main(string[] args) {
        try {
                Gtk.init_with_args(ref args, "[OPTION...]", entries, "systemd-ask-password-agent");
                Notify.init("Password Agent");

                MyStatusIcon i = new MyStatusIcon();
                Gtk.main();

        } catch (GLib.Error e) {
                show_error(e.message);
        }

        return 0;
}
