/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "busctl-introspect.h"
#include "set.h"
#include "strv.h"
#include "tests.h"

static const char *xml_root =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                  "<node>\n"
                  " <interface name=\"org.freedesktop.DBus.Peer\">\n"
                  "  <method name=\"Ping\"/>\n"
                  "  <method name=\"GetMachineId\">\n"
                  "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                  "  <method name=\"Introspect\">\n"
                  "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Properties\">\n"
                  "  <method name=\"Get\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <method name=\"GetAll\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"
                  "  </method>\n"
                  "  <method name=\"Set\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <signal name=\"PropertiesChanged\">\n"
                  "   <arg type=\"s\" name=\"interface\"/>\n"
                  "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"
                  "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"
                  "  </signal>\n"
                  " </interface>\n"
                  " <node name=\"org\"/>\n"
                  "</node>\n";

static const char *xml_org =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                  "<node>\n"
                  " <interface name=\"org.freedesktop.DBus.Peer\">\n"
                  "  <method name=\"Ping\"/>\n"
                  "  <method name=\"GetMachineId\">\n"
                  "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                  "  <method name=\"Introspect\">\n"
                  "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Properties\">\n"
                  "  <method name=\"Get\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <method name=\"GetAll\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"
                  "  </method>\n"
                  "  <method name=\"Set\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <signal name=\"PropertiesChanged\">\n"
                  "   <arg type=\"s\" name=\"interface\"/>\n"
                  "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"
                  "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"
                  "  </signal>\n"
                  " </interface>\n"
                  " <node name=\"freedesktop\"/>\n"
                  "</node>\n";

static const char *xml_org_freedesktop =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                  "<node>\n"
                  " <interface name=\"org.freedesktop.DBus.Peer\">\n"
                  "  <method name=\"Ping\"/>\n"
                  "  <method name=\"GetMachineId\">\n"
                  "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                  "  <method name=\"Introspect\">\n"
                  "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Properties\">\n"
                  "  <method name=\"Get\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <method name=\"GetAll\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"
                  "  </method>\n"
                  "  <method name=\"Set\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <signal name=\"PropertiesChanged\">\n"
                  "   <arg type=\"s\" name=\"interface\"/>\n"
                  "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"
                  "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"
                  "  </signal>\n"
                  " </interface>\n"
                  " <node name=\"LogControl1\"/>\n"
                  " <node name=\"network1\"/>\n"
                  "</node>\n";

static const char *xml_org_freedesktop_LogControl1 =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                  "<node>\n"
                  " <interface name=\"org.freedesktop.DBus.Peer\">\n"
                  "  <method name=\"Ping\"/>\n"
                  "  <method name=\"GetMachineId\">\n"
                  "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                  "  <method name=\"Introspect\">\n"
                  "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Properties\">\n"
                  "  <method name=\"Get\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <method name=\"GetAll\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"
                  "  </method>\n"
                  "  <method name=\"Set\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <signal name=\"PropertiesChanged\">\n"
                  "   <arg type=\"s\" name=\"interface\"/>\n"
                  "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"
                  "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"
                  "  </signal>\n"
                  " </interface>\n"
                  "<interface name=\"org.freedesktop.LogControl1\">\n"
                  "  <property name=\"LogLevel\" type=\"s\" access=\"readwrite\">\n"
                  "   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"false\"/>\n"
                  "   <annotation name=\"org.freedesktop.systemd1.Privileged\" value=\"true\"/>\n"
                  "  </property>\n"
                  "  <property name=\"LogTarget\" type=\"s\" access=\"readwrite\">\n"
                  "   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"false\"/>\n"
                  "   <annotation name=\"org.freedesktop.systemd1.Privileged\" value=\"true\"/>\n"
                  "  </property>\n"
                  "  <property name=\"SyslogIdentifier\" type=\"s\" access=\"read\">\n"
                  "   <annotation name=\"org.freedesktop.DBus.Property.EmitsChangedSignal\" value=\"false\"/>\n"
                  "  </property>\n"
                  " </interface>\n"
                  "</node>\n";

static const char *xml_org_freedesktop_network1 =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                  "<node>\n"
                  " <interface name=\"org.freedesktop.DBus.Peer\">\n"
                  "  <method name=\"Ping\"/>\n"
                  "  <method name=\"GetMachineId\">\n"
                  "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                  "  <method name=\"Introspect\">\n"
                  "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Properties\">\n"
                  "  <method name=\"Get\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <method name=\"GetAll\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"
                  "  </method>\n"
                  "  <method name=\"Set\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <signal name=\"PropertiesChanged\">\n"
                  "   <arg type=\"s\" name=\"interface\"/>\n"
                  "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"
                  "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"
                  "  </signal>\n"
                  " </interface>\n"
                  " <node name=\"network\"/>\n"
                  "</node>\n";

static const char *xml_org_freedesktop_network1_network =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                  "<node>\n"
                  " <interface name=\"org.freedesktop.DBus.Peer\">\n"
                  "  <method name=\"Ping\"/>\n"
                  "  <method name=\"GetMachineId\">\n"
                  "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                  "  <method name=\"Introspect\">\n"
                  "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Properties\">\n"
                  "  <method name=\"Get\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <method name=\"GetAll\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"
                  "  </method>\n"
                  "  <method name=\"Set\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <signal name=\"PropertiesChanged\">\n"
                  "   <arg type=\"s\" name=\"interface\"/>\n"
                  "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"
                  "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"
                  "  </signal>\n"
                  " </interface>\n"
                  " <node name=\"0\"/>\n"
                  " <node name=\"1\"/>\n"
                  " <node name=\"2\"/>\n"
                  " <node name=\"3\"/>\n"
                  " <node name=\"4\"/>\n"
                  " <node name=\"5\"/>\n"
                  " <node name=\"6\"/>\n"
                  " <node name=\"7\"/>\n"
                  " <node name=\"8\"/>\n"
                  " <node name=\"9\"/>\n"
                  " <node name=\"10\"/>\n"
                  " <node name=\"11\"/>\n"
                  " <node name=\"12\"/>\n"
                  " <node name=\"13\"/>\n"
                  " <node name=\"14\"/>\n"
                  " <node name=\"15\"/>\n"
                  " <node name=\"16\"/>\n"
                  " <node name=\"17\"/>\n"
                  " <node name=\"18\"/>\n"
                  " <node name=\"19\"/>\n"
                  " <node name=\"20\"/>\n"
                  "</node>\n";

static const char *xml_org_freedesktop_network1_network_unsigned =
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
                  "<node>\n"
                  " <interface name=\"org.freedesktop.DBus.Peer\">\n"
                  "  <method name=\"Ping\"/>\n"
                  "  <method name=\"GetMachineId\">\n"
                  "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
                  "  <method name=\"Introspect\">\n"
                  "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"
                  "  </method>\n"
                  " </interface>\n"
                  " <interface name=\"org.freedesktop.DBus.Properties\">\n"
                  "  <method name=\"Get\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <method name=\"GetAll\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n"
                  "  </method>\n"
                  "  <method name=\"Set\">\n"
                  "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"
                  "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"
                  "  </method>\n"
                  "  <signal name=\"PropertiesChanged\">\n"
                  "   <arg type=\"s\" name=\"interface\"/>\n"
                  "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"
                  "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"
                  "  </signal>\n"
                  " </interface>\n"
                  " <node name=\"hoge\"/>\n"
                  "</node>\n";

static int on_path(const char *path, void *userdata) {
        Set *paths = userdata;

        assert_se(paths);
        assert_se(set_put_strdup(&paths, path) >= 0);

        return 0;
}

static void test_introspect_on_path(void) {
        static const XMLIntrospectOps ops = {
                .on_path = on_path,
        };
        _cleanup_strv_free_ char **expected = NULL;
        _cleanup_set_free_ Set *paths = NULL;
        _cleanup_free_ char **l = NULL;

        log_info("/* %s */", __func__);

        assert_se(set_put_strdup(&paths, "/") > 0);

        log_debug("/* parse_xml_introspect(\"/\") */");
        assert_se(parse_xml_introspect("/", xml_root, &ops, paths) >= 0);
        log_debug("/* parse_xml_introspect(\"/org\") */");
        assert_se(parse_xml_introspect("/org", xml_org, &ops, paths) >= 0);
        log_debug("/* parse_xml_introspect(\"/org/freedesktop\") */");
        assert_se(parse_xml_introspect("/org/freedesktop", xml_org_freedesktop, &ops, paths) >= 0);
        log_debug("/* parse_xml_introspect(\"/org/freedesktop/LogControl1\") */");
        assert_se(parse_xml_introspect("/org/freedesktop/LogControl1", xml_org_freedesktop_LogControl1, &ops, paths) >= 0);
        log_debug("/* parse_xml_introspect(\"/org/freedesktop/network1\") */");
        assert_se(parse_xml_introspect("/org/freedesktop/network1", xml_org_freedesktop_network1, &ops, paths) >= 0);
        log_debug("/* parse_xml_introspect(\"/org/freedesktop/network1/network\") */");
        assert_se(parse_xml_introspect("/org/freedesktop/network1/network", xml_org_freedesktop_network1_network, &ops, paths) >= 0);
        for (unsigned i = 0; i <= 20; i++) {
                _cleanup_free_ char *path = NULL;

                assert_se(asprintf(&path, "/org/freedesktop/network1/network/%u", i) >= 0);
                log_debug("/* parse_xml_introspect(\"%s\") */", path);
                assert_se(parse_xml_introspect(path, xml_org_freedesktop_network1_network_unsigned, &ops, paths) >= 0);
        }

        assert_se(l = set_get_strv(paths));
        strv_sort(l);

        assert_se(strv_extend(&expected, "/") >= 0);
        assert_se(strv_extend(&expected, "/org") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/LogControl1") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/0") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/0/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/1") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/1/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/2") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/2/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/3") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/3/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/4") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/4/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/5") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/5/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/6") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/6/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/7") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/7/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/8") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/8/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/9") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/9/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/10") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/10/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/11") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/11/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/12") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/12/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/13") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/13/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/14") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/14/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/15") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/15/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/16") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/16/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/17") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/17/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/18") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/18/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/19") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/19/hoge") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/20") >= 0);
        assert_se(strv_extend(&expected, "/org/freedesktop/network1/network/20/hoge") >= 0);

        strv_sort(expected);
        assert_se(strv_equal(l, expected));
}

int main(int argc, char *argv[]) {
        test_setup_logging(LOG_DEBUG);

        test_introspect_on_path();

        return 0;
}
