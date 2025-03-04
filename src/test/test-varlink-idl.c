/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>

#include "sd-varlink.h"
#include "sd-varlink-idl.h"

#include "fd-util.h"
#include "pretty-print.h"
#include "tests.h"
#include "varlink-idl-util.h"
#include "varlink-io.systemd.h"
#include "varlink-io.systemd.BootControl.h"
#include "varlink-io.systemd.AskPassword.h"
#include "varlink-io.systemd.Credentials.h"
#include "varlink-io.systemd.Import.h"
#include "varlink-io.systemd.Journal.h"
#include "varlink-io.systemd.Login.h"
#include "varlink-io.systemd.Machine.h"
#include "varlink-io.systemd.MachineImage.h"
#include "varlink-io.systemd.ManagedOOM.h"
#include "varlink-io.systemd.MountFileSystem.h"
#include "varlink-io.systemd.NamespaceResource.h"
#include "varlink-io.systemd.Network.h"
#include "varlink-io.systemd.PCRExtend.h"
#include "varlink-io.systemd.PCRLock.h"
#include "varlink-io.systemd.Resolve.h"
#include "varlink-io.systemd.Resolve.Monitor.h"
#include "varlink-io.systemd.Udev.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink-io.systemd.oom.h"
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
        _cleanup_(varlink_interface_freep) sd_varlink_interface *parsed = NULL;
        _cleanup_free_ char *text = NULL, *text2 = NULL;

        assert_se(iface);

        assert_se(sd_varlink_idl_dump(stdout, iface, SD_VARLINK_IDL_FORMAT_COLOR, /* cols= */ SIZE_MAX) >= 0);
        assert_se(varlink_idl_consistent(iface, LOG_ERR) >= 0);
        assert_se(sd_varlink_idl_format(iface, &text) >= 0);
        assert_se(varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        assert_se(varlink_idl_consistent(parsed, LOG_ERR) >= 0);
        assert_se(sd_varlink_idl_format(parsed, &text2) >= 0);

        ASSERT_STREQ(text, text2);

        text = mfree(text);
        text2 = mfree(text2);
        parsed = varlink_interface_free(parsed);

        /* Do the same thing, but aggressively line break, and make sure this is roundtrippable as well */
        assert_se(sd_varlink_idl_dump(stdout, iface, SD_VARLINK_IDL_FORMAT_COLOR, 23) >= 0);
        assert_se(varlink_idl_consistent(iface, LOG_ERR) >= 0);
        assert_se(sd_varlink_idl_format_full(iface, 0, 23, &text) >= 0);
        assert_se(varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        assert_se(varlink_idl_consistent(parsed, LOG_ERR) >= 0);
        assert_se(sd_varlink_idl_format_full(parsed, 0, 23, &text2) >= 0);

        ASSERT_STREQ(text, text2);
}

TEST(parse_format) {
        test_parse_format_one(&vl_interface_org_varlink_service);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_UserDatabase);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_NamespaceResource);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Journal);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Resolve);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Resolve_Monitor);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_ManagedOOM);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_MountFileSystem);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Network);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_oom);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_PCRExtend);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_PCRLock);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_service);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_sysext);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Credentials);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_BootControl);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Import);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Machine);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_MachineImage);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_AskPassword);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Udev);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_Login);
        print_separator();
        test_parse_format_one(&vl_interface_xyz_test);
}

TEST(parse) {
        _cleanup_(varlink_interface_freep) sd_varlink_interface *parsed = NULL;

        /* This one has (nested) enonymous enums and structs */
        static const char text[] =
                "interface quu.waa\n"
                "type Fooenum ( a, b, c )\n"
                "type Barstruct ( a : (x, y, z), b : (x : int), c: (f, ff, fff), d: object, e : (sub : (subsub: (subsubsub: string, subsubsub2: (iii, ooo)))))"
                ;

        assert_se(varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        test_parse_format_one(parsed);

        assert_se(varlink_idl_parse("interface org.freedesktop.Foo\n"
                                    "type Foo (b: bool, c: foo, c: int)", NULL, NULL, NULL) == -ENETUNREACH); /* unresolved type */
        assert_se(varlink_idl_parse("interface org.freedesktop.Foo\n"
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

        _cleanup_(varlink_interface_freep) sd_varlink_interface *parsed = NULL;

        /* This one has (nested) enonymous enums and structs */
        static const char text[] =
                "interface validate.test\n"
                "method Mymethod ( \n"
                "# piff   \n"
                "a:string,\n"
                "#paff\n"
                "b:int, c:?bool, d:[]int, e:?[string]bool, f:?(piff, paff), g:(f:float) ) -> ()\n";

        assert_se(varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
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
        _cleanup_(varlink_interface_freep) sd_varlink_interface *parsed = NULL;
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

        return varlink_idl_parse(text, NULL, NULL, &parsed);
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

DEFINE_TEST_MAIN(LOG_DEBUG);
