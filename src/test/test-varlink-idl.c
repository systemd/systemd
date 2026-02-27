/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "sd-varlink.h"
#include "sd-varlink-idl.h"

#include "bootspec.h"
#include "discover-image.h"
#include "fd-util.h"
#include "gpt.h"
#include "json-util.h"
#include "network-util.h"
#include "pretty-print.h"
#include "resolve-util.h"
#include "tests.h"
#include "varlink-idl-util.h"
#include "varlink-io.systemd.h"
#include "varlink-io.systemd.AskPassword.h"
#include "varlink-io.systemd.BootControl.h"
#include "varlink-io.systemd.Credentials.h"
#include "varlink-io.systemd.FactoryReset.h"
#include "varlink-io.systemd.Hostname.h"
#include "varlink-io.systemd.Import.h"
#include "varlink-io.systemd.Journal.h"
#include "varlink-io.systemd.JournalAccess.h"
#include "varlink-io.systemd.Login.h"
#include "varlink-io.systemd.Machine.h"
#include "varlink-io.systemd.MachineImage.h"
#include "varlink-io.systemd.ManagedOOM.h"
#include "varlink-io.systemd.Manager.h"
#include "varlink-io.systemd.MountFileSystem.h"
#include "varlink-io.systemd.MuteConsole.h"
#include "varlink-io.systemd.NamespaceResource.h"
#include "varlink-io.systemd.Network.h"
#include "varlink-io.systemd.Network.Link.h"
#include "varlink-io.systemd.PCRExtend.h"
#include "varlink-io.systemd.PCRLock.h"
#include "varlink-io.systemd.Repart.h"
#include "varlink-io.systemd.Resolve.h"
#include "varlink-io.systemd.Resolve.Hook.h"
#include "varlink-io.systemd.Resolve.Monitor.h"
#include "varlink-io.systemd.Udev.h"
#include "varlink-io.systemd.Unit.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink-io.systemd.oom.h"
#include "varlink-io.systemd.oom.Prekill.h"
#include "varlink-io.systemd.service.h"
#include "varlink-io.systemd.sysext.h"
#include "varlink-org.varlink.service.h"
#include "varlink-util.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                EnumTest,
                SD_VARLINK_FIELD_COMMENT("piff paff"),
                SD_VARLINK_DEFINE_ENUM_VALUE(foo),
                SD_VARLINK_FIELD_COMMENT("waldo"),
                SD_VARLINK_DEFINE_ENUM_VALUE(bar),
                SD_VARLINK_FIELD_COMMENT("crux"),
                SD_VARLINK_DEFINE_ENUM_VALUE(baz));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                NestedStructTest,
                SD_VARLINK_FIELD_COMMENT("miepf"),
                SD_VARLINK_DEFINE_FIELD(x, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                StructTest,

                SD_VARLINK_DEFINE_FIELD(bbb, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD(bbbn, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(bbba, SD_VARLINK_BOOL, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(bbbna, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(bbbm, SD_VARLINK_BOOL, SD_VARLINK_MAP),
                SD_VARLINK_DEFINE_FIELD(bbbnm, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE|SD_VARLINK_MAP),

                SD_VARLINK_FIELD_COMMENT("more from here"),

                SD_VARLINK_DEFINE_FIELD(iii, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_FIELD(iiin, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(iiia, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(iiina, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(iiim, SD_VARLINK_INT, SD_VARLINK_MAP),
                SD_VARLINK_DEFINE_FIELD(iiinm, SD_VARLINK_INT, SD_VARLINK_NULLABLE|SD_VARLINK_MAP),

                SD_VARLINK_DEFINE_FIELD(fff, SD_VARLINK_FLOAT, 0),
                SD_VARLINK_DEFINE_FIELD(fffn, SD_VARLINK_FLOAT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(fffa, SD_VARLINK_FLOAT, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(fffna, SD_VARLINK_FLOAT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(fffm, SD_VARLINK_FLOAT, SD_VARLINK_MAP),
                SD_VARLINK_DEFINE_FIELD(fffnm, SD_VARLINK_FLOAT, SD_VARLINK_NULLABLE|SD_VARLINK_MAP),

                SD_VARLINK_DEFINE_FIELD(sss, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_FIELD(sssn, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(sssa, SD_VARLINK_STRING, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(sssna, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(sssm, SD_VARLINK_STRING, SD_VARLINK_MAP),
                SD_VARLINK_DEFINE_FIELD(sssnm, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_MAP),

                SD_VARLINK_DEFINE_FIELD(ooo, SD_VARLINK_OBJECT, 0),
                SD_VARLINK_DEFINE_FIELD(ooon, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(oooa, SD_VARLINK_OBJECT, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(ooona, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(ooom, SD_VARLINK_OBJECT, SD_VARLINK_MAP),
                SD_VARLINK_DEFINE_FIELD(ooonm, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE|SD_VARLINK_MAP),

                SD_VARLINK_DEFINE_FIELD(aaa, SD_VARLINK_ANY, 0),
                SD_VARLINK_DEFINE_FIELD(aaan, SD_VARLINK_ANY, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD(aaaa, SD_VARLINK_ANY, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(aaana, SD_VARLINK_ANY, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD(aaam, SD_VARLINK_ANY, SD_VARLINK_MAP),
                SD_VARLINK_DEFINE_FIELD(aaanm, SD_VARLINK_ANY, SD_VARLINK_NULLABLE|SD_VARLINK_MAP),

                SD_VARLINK_DEFINE_FIELD_BY_TYPE(eee, EnumTest, 0),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(eeen, EnumTest, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(eeea, EnumTest, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(eeena, EnumTest, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(eeem, EnumTest, SD_VARLINK_MAP),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(eeenm, EnumTest, SD_VARLINK_NULLABLE|SD_VARLINK_MAP),

                SD_VARLINK_DEFINE_FIELD_BY_TYPE(nnn, NestedStructTest, 0),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(nnnn, NestedStructTest, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(nnna, NestedStructTest, SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(nnnna, NestedStructTest, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(nnnm, NestedStructTest, SD_VARLINK_MAP),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(nnnnm, NestedStructTest, SD_VARLINK_NULLABLE|SD_VARLINK_MAP));

static SD_VARLINK_DEFINE_METHOD(
                MethodTest,
                SD_VARLINK_DEFINE_INPUT(x, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(y, EnumTest, 0),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(z, StructTest, 0),
                SD_VARLINK_DEFINE_OUTPUT(x, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(y, EnumTest, 0),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(z, StructTest, 0));

static SD_VARLINK_DEFINE_ERROR(
                ErrorTest,
                SD_VARLINK_DEFINE_FIELD(x, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(y, EnumTest, 0),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(z, StructTest, 0));

static SD_VARLINK_DEFINE_INTERFACE(
                xyz_test,
                "xyz.test",
                &vl_type_EnumTest,
                &vl_type_NestedStructTest,
                &vl_type_StructTest,
                &vl_method_MethodTest,
                &vl_error_ErrorTest);

static void test_parse_format_one(const sd_varlink_interface *iface) {
        _cleanup_(sd_varlink_interface_freep) sd_varlink_interface *parsed = NULL;
        _cleanup_free_ char *text = NULL, *text2 = NULL;

        assert_se(iface);

        assert_se(sd_varlink_idl_dump(stdout, iface, SD_VARLINK_IDL_FORMAT_COLOR, /* cols= */ SIZE_MAX) >= 0);
        assert_se(varlink_idl_consistent(iface, LOG_ERR) >= 0);
        assert_se(sd_varlink_idl_format(iface, &text) >= 0);
        assert_se(sd_varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        assert_se(varlink_idl_consistent(parsed, LOG_ERR) >= 0);
        assert_se(sd_varlink_idl_format(parsed, &text2) >= 0);

        ASSERT_STREQ(text, text2);

        text = mfree(text);
        text2 = mfree(text2);
        parsed = sd_varlink_interface_free(parsed);

        /* Do the same thing, but aggressively line break, and make sure this is roundtrippable as well */
        assert_se(sd_varlink_idl_dump(stdout, iface, SD_VARLINK_IDL_FORMAT_COLOR, 23) >= 0);
        assert_se(varlink_idl_consistent(iface, LOG_ERR) >= 0);
        assert_se(sd_varlink_idl_format_full(iface, 0, 23, &text) >= 0);
        assert_se(sd_varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        assert_se(varlink_idl_consistent(parsed, LOG_ERR) >= 0);
        assert_se(sd_varlink_idl_format_full(parsed, 0, 23, &text2) >= 0);

        ASSERT_STREQ(text, text2);
}

TEST(parse_format) {
        const sd_varlink_interface* const list[] = {
                &vl_interface_io_systemd,
                &vl_interface_io_systemd_AskPassword,
                &vl_interface_io_systemd_BootControl,
                &vl_interface_io_systemd_Credentials,
                &vl_interface_io_systemd_FactoryReset,
                &vl_interface_io_systemd_Hostname,
                &vl_interface_io_systemd_Import,
                &vl_interface_io_systemd_Journal,
                &vl_interface_io_systemd_JournalAccess,
                &vl_interface_io_systemd_Login,
                &vl_interface_io_systemd_Machine,
                &vl_interface_io_systemd_MachineImage,
                &vl_interface_io_systemd_ManagedOOM,
                &vl_interface_io_systemd_Manager,
                &vl_interface_io_systemd_MountFileSystem,
                &vl_interface_io_systemd_MuteConsole,
                &vl_interface_io_systemd_NamespaceResource,
                &vl_interface_io_systemd_Network,
                &vl_interface_io_systemd_Network_Link,
                &vl_interface_io_systemd_PCRExtend,
                &vl_interface_io_systemd_PCRLock,
                &vl_interface_io_systemd_Repart,
                &vl_interface_io_systemd_Resolve,
                &vl_interface_io_systemd_Resolve_Hook,
                &vl_interface_io_systemd_Resolve_Monitor,
                &vl_interface_io_systemd_Udev,
                &vl_interface_io_systemd_Unit,
                &vl_interface_io_systemd_UserDatabase,
                &vl_interface_io_systemd_oom,
                &vl_interface_io_systemd_oom_Prekill,
                &vl_interface_io_systemd_service,
                &vl_interface_io_systemd_sysext,
                &vl_interface_org_varlink_service,
                &vl_interface_xyz_test,
        };

        bool sep = false;
        FOREACH_ELEMENT(i, list) {
                if (sep)
                        print_separator();
                test_parse_format_one(*i);
                sep = true;
        }
}

TEST(parse) {
        _cleanup_(sd_varlink_interface_freep) sd_varlink_interface *parsed = NULL;

        /* This one has (nested) enonymous enums and structs */
        static const char text[] =
                "interface quu.waa\n"
                "type Fooenum ( a, b, c )\n"
                "type Barstruct ( a : (x, y, z), b : (x : int), c: (f, ff, fff), d: object, e : (sub : (subsub: (subsubsub: string, subsubsub2: (iii, ooo)))))"
                ;

        assert_se(sd_varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        test_parse_format_one(parsed);

        assert_se(sd_varlink_idl_parse("interface org.freedesktop.Foo\n"
                                       "type Foo (b: bool, c: foo, c: int)", NULL, NULL, NULL) == -ENETUNREACH); /* unresolved type */
        assert_se(sd_varlink_idl_parse("interface org.freedesktop.Foo\n"
                                       "type Foo ()", NULL, NULL, NULL) == -EBADMSG); /* empty struct/enum */
}

TEST(interface_name_is_valid) {
        assert_se(!varlink_idl_interface_name_is_valid(NULL));
        assert_se(!varlink_idl_interface_name_is_valid(""));
        assert_se(!varlink_idl_interface_name_is_valid(","));
        assert_se(!varlink_idl_interface_name_is_valid("."));
        assert_se(!varlink_idl_interface_name_is_valid("-"));
        assert_se(varlink_idl_interface_name_is_valid("a"));
        assert_se(varlink_idl_interface_name_is_valid("a.a"));
        assert_se(!varlink_idl_interface_name_is_valid("-.a"));
        assert_se(!varlink_idl_interface_name_is_valid("-a.a"));
        assert_se(!varlink_idl_interface_name_is_valid("a-.a"));
        assert_se(varlink_idl_interface_name_is_valid("a-a.a"));
        assert_se(!varlink_idl_interface_name_is_valid("a-a.a-"));
        assert_se(!varlink_idl_interface_name_is_valid("a-a.-a"));
        assert_se(!varlink_idl_interface_name_is_valid("a-a.-"));
        assert_se(varlink_idl_interface_name_is_valid("a-a.a-a"));
        assert_se(varlink_idl_interface_name_is_valid("io.systemd.Foobar"));
}

TEST(symbol_name_is_valid) {
        assert_se(!varlink_idl_symbol_name_is_valid(NULL));
        assert_se(!varlink_idl_symbol_name_is_valid(""));
        assert_se(!varlink_idl_symbol_name_is_valid("_"));
        assert_se(!varlink_idl_symbol_name_is_valid("_foo"));
        assert_se(varlink_idl_symbol_name_is_valid("Foofoo"));
        assert_se(varlink_idl_symbol_name_is_valid("Foo"));
        assert_se(varlink_idl_symbol_name_is_valid("Foo0"));
        assert_se(!varlink_idl_symbol_name_is_valid("0Foo"));
        assert_se(!varlink_idl_symbol_name_is_valid("foo"));
        assert_se(varlink_idl_symbol_name_is_valid("Foo0foo"));
        assert_se(!varlink_idl_symbol_name_is_valid("bool"));
        assert_se(!varlink_idl_symbol_name_is_valid("int"));
        assert_se(!varlink_idl_symbol_name_is_valid("float"));
        assert_se(!varlink_idl_symbol_name_is_valid("string"));
        assert_se(!varlink_idl_symbol_name_is_valid("object"));
        assert_se(!varlink_idl_symbol_name_is_valid("any"));
}

TEST(field_name_is_valid) {
        assert_se(!varlink_idl_field_name_is_valid(NULL));
        assert_se(!varlink_idl_field_name_is_valid(""));
        assert_se(!varlink_idl_field_name_is_valid("_"));
        assert_se(!varlink_idl_field_name_is_valid("_foo"));
        assert_se(!varlink_idl_field_name_is_valid("_foo_"));
        assert_se(!varlink_idl_field_name_is_valid("foo_"));
        assert_se(varlink_idl_field_name_is_valid("foo_foo"));
        assert_se(varlink_idl_field_name_is_valid("f_o_o_f_o_o"));
        assert_se(!varlink_idl_field_name_is_valid("foo__foo"));
        assert_se(varlink_idl_field_name_is_valid("Foofoo"));
        assert_se(varlink_idl_field_name_is_valid("Foo"));
        assert_se(varlink_idl_field_name_is_valid("Foo0"));
        assert_se(!varlink_idl_field_name_is_valid("0Foo"));
        assert_se(varlink_idl_field_name_is_valid("foo"));
        assert_se(varlink_idl_field_name_is_valid("Foo0foo"));
        assert_se(varlink_idl_field_name_is_valid("foo0foo"));
}

TEST(qualified_symbol_name_is_valid) {
        assert_se(varlink_idl_qualified_symbol_name_is_valid(NULL) == 0);
        assert_se(varlink_idl_qualified_symbol_name_is_valid("") == 0);
        assert_se(varlink_idl_qualified_symbol_name_is_valid("x") == 0);
        assert_se(varlink_idl_qualified_symbol_name_is_valid("xxx") == 0);
        assert_se(varlink_idl_qualified_symbol_name_is_valid("xxx.xxx") == 0);
        assert_se(varlink_idl_qualified_symbol_name_is_valid("xxx.Xxx") > 0);
        assert_se(varlink_idl_qualified_symbol_name_is_valid("xxx.xxx.XXX") > 0);
        assert_se(varlink_idl_qualified_symbol_name_is_valid("xxx.xxx.0foo") == 0);
}

TEST(validate_json) {

        _cleanup_(sd_varlink_interface_freep) sd_varlink_interface *parsed = NULL;

        /* This one has (nested) enonymous enums and structs */
        static const char text[] =
                "interface validate.test\n"
                "method Mymethod ( \n"
                "# piff   \n"
                "a:string,\n"
                "#paff\n"
                "b:int, c:?bool, d:[]int, e:?[string]bool, f:?(piff, paff), g:(f:float) ) -> ()\n";

        assert_se(sd_varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        test_parse_format_one(parsed);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        assert_se(sd_json_build(&v, SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR("a", SD_JSON_BUILD_STRING("x")),
                                             SD_JSON_BUILD_PAIR("b", SD_JSON_BUILD_UNSIGNED(44)),
                                             SD_JSON_BUILD_PAIR("d", SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_UNSIGNED(5), SD_JSON_BUILD_UNSIGNED(7), SD_JSON_BUILD_UNSIGNED(107))),
                                             SD_JSON_BUILD_PAIR("g", SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR("f", SD_JSON_BUILD_REAL(0.5f)))))) >= 0);

        sd_json_variant_dump(v, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, stdout, NULL);

        const sd_varlink_symbol* symbol = ASSERT_PTR(varlink_idl_find_symbol(parsed, SD_VARLINK_METHOD, "Mymethod"));

        assert_se(varlink_idl_validate_method_call(symbol, v, /* flags= */ 0, /* reterr_bad_field= */ NULL) >= 0);
}

static int test_recursive_one(unsigned depth) {
        _cleanup_(sd_varlink_interface_freep) sd_varlink_interface *parsed = NULL;
        _cleanup_free_ char *pre = NULL, *post = NULL, *text = NULL;
        static const char header[] =
                "interface recursive.test\n"
                "type Foo (\n";

        /* Generate a chain of nested structures, i.e. a: (a: (... (int))...) */
        pre = strrep("a:(", depth);
        post = strrep(")", depth);
        if (!pre || !post)
                return log_oom();

        text = strjoin(header, pre, "int", post, ")");
        if (!text)
                return log_oom();

        return sd_varlink_idl_parse(text, NULL, NULL, &parsed);
}

TEST(recursive) {
        assert_se(test_recursive_one(32) >= 0);
        assert_se(test_recursive_one(64) >= 0);

        /* We should handle this gracefully without a stack overflow */
        assert_se(test_recursive_one(65) < 0);
        assert_se(test_recursive_one(20000) < 0 );
}

static int test_method(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        sd_json_variant *foo = sd_json_variant_by_key(parameters, "foo"), *bar = sd_json_variant_by_key(parameters, "bar");

        return sd_varlink_replyb(link,
                              SD_JSON_BUILD_OBJECT(
                                              SD_JSON_BUILD_PAIR_UNSIGNED("waldo", sd_json_variant_unsigned(foo) * sd_json_variant_unsigned(bar)),
                                              SD_JSON_BUILD_PAIR_UNSIGNED("quux", sd_json_variant_unsigned(foo) + sd_json_variant_unsigned(bar))));
}

static int done_method(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        assert_se(sd_event_exit(sd_varlink_get_event(link), 0) >= 0);
        return 0;
}

static SD_VARLINK_DEFINE_METHOD(
                TestMethod,
                SD_VARLINK_DEFINE_INPUT(foo, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(bar, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(optional, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(waldo, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_OUTPUT(quux, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(Done);

static SD_VARLINK_DEFINE_INTERFACE(
                xyz,
                "xyz",
                &vl_method_TestMethod,
                &vl_method_Done);

static void* server_thread(void *userdata) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *server = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;

        assert_se(sd_varlink_server_new(&server, 0) >= 0);
        assert_se(varlink_set_info_systemd(server) >= 0);
        assert_se(sd_varlink_server_add_interface(server, &vl_interface_xyz) >= 0);
        assert_se(sd_varlink_server_bind_method(server, "xyz.TestMethod", test_method) >= 0);
        assert_se(sd_varlink_server_bind_method(server, "xyz.Done", done_method) >= 0);

        assert_se(sd_event_new(&event) >= 0);
        assert_se(sd_varlink_server_attach_event(server, event, 0) >= 0);

        assert_se(sd_varlink_server_add_connection(server, PTR_TO_FD(userdata), NULL) >= 0);

        assert_se(sd_event_loop(event) >= 0);
        return NULL;
}

TEST(validate_method_call) {
        _cleanup_close_pair_ int fd[2] = EBADF_PAIR;
        _cleanup_(sd_varlink_unrefp) sd_varlink *v = NULL;
        pthread_t t;

        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, fd) >= 0);
        assert_se(pthread_create(&t, NULL, server_thread, FD_TO_PTR(TAKE_FD(fd[1]))) == 0);
        assert_se(sd_varlink_connect_fd(&v, TAKE_FD(fd[0])) >= 0);

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        assert_se(sd_varlink_callb(v, "xyz.TestMethod", &reply, &error_id,
                                SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_UNSIGNED("foo", 8),
                                                SD_JSON_BUILD_PAIR_UNSIGNED("bar", 9))) >= 0);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *expected_reply = NULL;
        assert_se(sd_json_build(&expected_reply,
                             SD_JSON_BUILD_OBJECT(
                                             SD_JSON_BUILD_PAIR_UNSIGNED("waldo", 8*9),
                                             SD_JSON_BUILD_PAIR_UNSIGNED("quux", 8+9))) >= 0);

        assert_se(!error_id);

        sd_json_variant_dump(reply, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL);
        sd_json_variant_dump(expected_reply, SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO, NULL, NULL);
        assert_se(sd_json_variant_equal(reply, expected_reply));

        assert_se(sd_varlink_callb(v, "xyz.TestMethod", &reply, &error_id,
                                SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_UNSIGNED("foo", 9),
                                                SD_JSON_BUILD_PAIR_UNSIGNED("bar", 8),
                                                SD_JSON_BUILD_PAIR_STRING("optional", "pfft"))) >= 0);

        assert_se(!error_id);
        assert_se(sd_json_variant_equal(reply, expected_reply));

        assert_se(sd_varlink_callb(v, "xyz.TestMethod", &reply, &error_id,
                                SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_UNSIGNED("foo", 8),
                                                SD_JSON_BUILD_PAIR_UNSIGNED("bar", 9),
                                                SD_JSON_BUILD_PAIR_STRING("zzz", "pfft"))) >= 0);
        ASSERT_STREQ(error_id, SD_VARLINK_ERROR_INVALID_PARAMETER);

        assert_se(sd_varlink_callb(v, "xyz.TestMethod", &reply, &error_id,
                                SD_JSON_BUILD_OBJECT(
                                                SD_JSON_BUILD_PAIR_BOOLEAN("foo", true),
                                                SD_JSON_BUILD_PAIR_UNSIGNED("bar", 9))) >= 0);
        ASSERT_STREQ(error_id, SD_VARLINK_ERROR_INVALID_PARAMETER);

        assert_se(sd_varlink_send(v, "xyz.Done", NULL) >= 0);
        assert_se(sd_varlink_flush(v) >= 0);
        assert_se(pthread_join(t, NULL) == 0);
}

static void test_enum_to_string_name(const char *n, const sd_varlink_symbol *symbol) {
        assert(n);
        assert(symbol);

        assert(symbol->symbol_type == SD_VARLINK_ENUM_TYPE);
        _cleanup_free_ char *m = ASSERT_PTR(json_underscorify(strdup(n)));

        bool found = false;
        for (const sd_varlink_field *f = symbol->fields; f->name; f++) {
                if (f->field_type == _SD_VARLINK_FIELD_COMMENT)
                        continue;

                assert(f->field_type == SD_VARLINK_ENUM_VALUE);
                if (streq(m, f->name)) {
                        found = true;
                        break;
                }
        }

        log_debug("'%s' found in '%s': %s", m, strna(symbol->name), yes_no(found));
        assert(found);
}

#define TEST_IDL_ENUM_TO_STRING(type, ename, symbol)     \
        for (type t = 0;; t++) {                         \
                const char *n = ename##_to_string(t);    \
                if (!n)                                  \
                        break;                           \
                test_enum_to_string_name(n, &(symbol));  \
        }

#define TEST_IDL_ENUM_FROM_STRING(type, ename, symbol)                  \
        for (const sd_varlink_field *f = (symbol).fields; f->name; f++) { \
                if (f->field_type == _SD_VARLINK_FIELD_COMMENT)         \
                        continue;                                       \
                assert(f->field_type == SD_VARLINK_ENUM_VALUE);         \
                _cleanup_free_ char *m = ASSERT_PTR(json_dashify(strdup(f->name))); \
                type t = ename##_from_string(m);                        \
                log_debug("'%s' of '%s' translates: %s", f->name, strna((symbol).name), yes_no(t >= 0)); \
                assert(t >= 0);                                         \
        }

#define TEST_IDL_ENUM(type, name, symbol)                       \
        do {                                                    \
                TEST_IDL_ENUM_TO_STRING(type, name, symbol);    \
                TEST_IDL_ENUM_FROM_STRING(type, name, symbol);  \
        } while (false)

TEST(enums_idl) {
        TEST_IDL_ENUM(BootEntryType, boot_entry_type, vl_type_BootEntryType);
        TEST_IDL_ENUM_TO_STRING(BootEntrySource, boot_entry_source, vl_type_BootEntrySource);

        TEST_IDL_ENUM(PartitionDesignator, partition_designator, vl_type_PartitionDesignator);

        TEST_IDL_ENUM(LinkAddressState, link_address_state, vl_type_LinkAddressState);
        TEST_IDL_ENUM_TO_STRING(LinkAddressState, link_address_state, vl_type_LinkAddressState);
        TEST_IDL_ENUM(LinkOnlineState, link_online_state, vl_type_LinkOnlineState);
        TEST_IDL_ENUM_TO_STRING(LinkOnlineState, link_online_state, vl_type_LinkOnlineState);
        TEST_IDL_ENUM(AddressFamily, link_required_address_family, vl_type_LinkRequiredAddressFamily);
        TEST_IDL_ENUM_TO_STRING(AddressFamily, link_required_address_family, vl_type_LinkRequiredAddressFamily);

        TEST_IDL_ENUM(DnsOverTlsMode, dns_over_tls_mode, vl_type_DNSOverTLSMode);
        TEST_IDL_ENUM(ResolveSupport, resolve_support, vl_type_ResolveSupport);

        TEST_IDL_ENUM(ImageType, image_type, vl_type_ImageType);
        TEST_IDL_ENUM_TO_STRING(ImageType, image_type, vl_type_ImageType);
}

static SD_VARLINK_DEFINE_METHOD(
                AnyTestStrict,
                SD_VARLINK_DEFINE_INPUT(foo, SD_VARLINK_ANY, 0),
                SD_VARLINK_DEFINE_INPUT(foo2, SD_VARLINK_ANY, 0),
                SD_VARLINK_DEFINE_INPUT(foo3, SD_VARLINK_ANY, 0),
                SD_VARLINK_DEFINE_INPUT(foo4, SD_VARLINK_ANY, 0));

static SD_VARLINK_DEFINE_METHOD(
                AnyTestNullable,
                SD_VARLINK_DEFINE_INPUT(foo, SD_VARLINK_ANY, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(foo2, SD_VARLINK_ANY, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(foo3, SD_VARLINK_ANY, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(foo4, SD_VARLINK_ANY, SD_VARLINK_NULLABLE));

TEST(any) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        ASSERT_OK(sd_json_buildo(&v,
                                 SD_JSON_BUILD_PAIR_STRING("foo", "bar"),
                                 SD_JSON_BUILD_PAIR_INTEGER("foo2", 47),
                                 SD_JSON_BUILD_PAIR_NULL("foo3"),
                                 SD_JSON_BUILD_PAIR_BOOLEAN("foo4", true)));

        /* "any" shall mean any type – but null */
        const char *bad_field = NULL;
        ASSERT_ERROR(varlink_idl_validate_method_call(&vl_method_AnyTestStrict, v, /* flags= */ 0, &bad_field), ENOANO);
        ASSERT_STREQ(bad_field, "foo3");

        /* "any?" shall many truly any type */
        bad_field = NULL;
        ASSERT_OK(varlink_idl_validate_method_call(&vl_method_AnyTestNullable, v, /* flags= */ 0, &bad_field));
        ASSERT_NULL(bad_field);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
