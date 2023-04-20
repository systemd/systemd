/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pthread.h>

#include "fd-util.h"
#include "pretty-print.h"
#include "tests.h"
#include "varlink.h"
#include "varlink-idl.h"
#include "varlink-io.systemd.h"
#include "varlink-io.systemd.Journal.h"
#include "varlink-io.systemd.ManagedOOM.h"
#include "varlink-io.systemd.MountFileSystem.h"
#include "varlink-io.systemd.NamespaceResource.h"
#include "varlink-io.systemd.PCRExtend.h"
#include "varlink-io.systemd.Resolve.h"
#include "varlink-io.systemd.Resolve.Monitor.h"
#include "varlink-io.systemd.UserDatabase.h"
#include "varlink-io.systemd.oom.h"
#include "varlink-io.systemd.service.h"
#include "varlink-io.systemd.sysext.h"
#include "varlink-org.varlink.service.h"

static VARLINK_DEFINE_ENUM_TYPE(
                EnumTest,
                VARLINK_DEFINE_ENUM_VALUE(foo),
                VARLINK_DEFINE_ENUM_VALUE(bar),
                VARLINK_DEFINE_ENUM_VALUE(baz));

static VARLINK_DEFINE_STRUCT_TYPE(
                NestedStructTest,
                VARLINK_DEFINE_FIELD(x, VARLINK_INT, 0));

static VARLINK_DEFINE_STRUCT_TYPE(
                StructTest,

                VARLINK_DEFINE_FIELD(bbb, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD(bbbn, VARLINK_BOOL, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(bbba, VARLINK_BOOL, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(bbbna, VARLINK_BOOL, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(bbbm, VARLINK_BOOL, VARLINK_MAP),
                VARLINK_DEFINE_FIELD(bbbnm, VARLINK_BOOL, VARLINK_NULLABLE|VARLINK_MAP),

                VARLINK_DEFINE_FIELD(iii, VARLINK_INT, 0),
                VARLINK_DEFINE_FIELD(iiin, VARLINK_INT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(iiia, VARLINK_INT, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(iiina, VARLINK_INT, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(iiim, VARLINK_INT, VARLINK_MAP),
                VARLINK_DEFINE_FIELD(iiinm, VARLINK_INT, VARLINK_NULLABLE|VARLINK_MAP),

                VARLINK_DEFINE_FIELD(fff, VARLINK_FLOAT, 0),
                VARLINK_DEFINE_FIELD(fffn, VARLINK_FLOAT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(fffa, VARLINK_FLOAT, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(fffna, VARLINK_FLOAT, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(fffm, VARLINK_FLOAT, VARLINK_MAP),
                VARLINK_DEFINE_FIELD(fffnm, VARLINK_FLOAT, VARLINK_NULLABLE|VARLINK_MAP),

                VARLINK_DEFINE_FIELD(sss, VARLINK_STRING, 0),
                VARLINK_DEFINE_FIELD(sssn, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(sssa, VARLINK_STRING, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(sssna, VARLINK_STRING, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(sssm, VARLINK_STRING, VARLINK_MAP),
                VARLINK_DEFINE_FIELD(sssnm, VARLINK_STRING, VARLINK_NULLABLE|VARLINK_MAP),

                VARLINK_DEFINE_FIELD(ooo, VARLINK_OBJECT, 0),
                VARLINK_DEFINE_FIELD(ooon, VARLINK_OBJECT, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD(oooa, VARLINK_OBJECT, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(ooona, VARLINK_OBJECT, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD(ooom, VARLINK_OBJECT, VARLINK_MAP),
                VARLINK_DEFINE_FIELD(ooonm, VARLINK_OBJECT, VARLINK_NULLABLE|VARLINK_MAP),

                VARLINK_DEFINE_FIELD_BY_TYPE(eee, EnumTest, 0),
                VARLINK_DEFINE_FIELD_BY_TYPE(eeen, EnumTest, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD_BY_TYPE(eeea, EnumTest, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD_BY_TYPE(eeena, EnumTest, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD_BY_TYPE(eeem, EnumTest, VARLINK_MAP),
                VARLINK_DEFINE_FIELD_BY_TYPE(eeenm, EnumTest, VARLINK_NULLABLE|VARLINK_MAP),

                VARLINK_DEFINE_FIELD_BY_TYPE(nnn, NestedStructTest, 0),
                VARLINK_DEFINE_FIELD_BY_TYPE(nnnn, NestedStructTest, VARLINK_NULLABLE),
                VARLINK_DEFINE_FIELD_BY_TYPE(nnna, NestedStructTest, VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD_BY_TYPE(nnnna, NestedStructTest, VARLINK_NULLABLE|VARLINK_ARRAY),
                VARLINK_DEFINE_FIELD_BY_TYPE(nnnm, NestedStructTest, VARLINK_MAP),
                VARLINK_DEFINE_FIELD_BY_TYPE(nnnnm, NestedStructTest, VARLINK_NULLABLE|VARLINK_MAP));

static VARLINK_DEFINE_METHOD(
                MethodTest,
                VARLINK_DEFINE_INPUT(x, VARLINK_BOOL, 0),
                VARLINK_DEFINE_INPUT_BY_TYPE(y, EnumTest, 0),
                VARLINK_DEFINE_INPUT_BY_TYPE(z, StructTest, 0),
                VARLINK_DEFINE_OUTPUT(x, VARLINK_BOOL, 0),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(y, EnumTest, 0),
                VARLINK_DEFINE_OUTPUT_BY_TYPE(z, StructTest, 0));

static VARLINK_DEFINE_ERROR(
                ErrorTest,
                VARLINK_DEFINE_FIELD(x, VARLINK_BOOL, 0),
                VARLINK_DEFINE_FIELD_BY_TYPE(y, EnumTest, 0),
                VARLINK_DEFINE_FIELD_BY_TYPE(z, StructTest, 0));

static VARLINK_DEFINE_INTERFACE(
                xyz_test,
                "xyz.test",
                &vl_type_EnumTest,
                &vl_type_NestedStructTest,
                &vl_type_StructTest,
                &vl_method_MethodTest,
                &vl_error_ErrorTest);

static void test_parse_format_one(const VarlinkInterface *iface) {
        _cleanup_(varlink_interface_freep) VarlinkInterface *parsed = NULL;
        _cleanup_free_ char *text = NULL, *text2 = NULL;

        assert_se(iface);

        assert_se(varlink_idl_dump(stdout, /* use_colors=*/ true, iface) >= 0);
        assert_se(varlink_idl_consistent(iface, LOG_ERR) >= 0);
        assert_se(varlink_idl_format(iface, &text) >= 0);
        assert_se(varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        assert_se(varlink_idl_consistent(parsed, LOG_ERR) >= 0);
        assert_se(varlink_idl_format(parsed, &text2) >= 0);
        assert_se(streq(text, text2));
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
        test_parse_format_one(&vl_interface_io_systemd_oom);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_PCRExtend);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_service);
        print_separator();
        test_parse_format_one(&vl_interface_io_systemd_sysext);
        print_separator();
        test_parse_format_one(&vl_interface_xyz_test);
}

TEST(parse) {
        _cleanup_(varlink_interface_freep) VarlinkInterface *parsed = NULL;

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

TEST(validate_json) {

        _cleanup_(varlink_interface_freep) VarlinkInterface *parsed = NULL;

        /* This one has (nested) enonymous enums and structs */
        static const char text[] =
                "interface validate.test\n"
                "method Mymethod ( a:string, b:int, c:?bool, d:[]int, e:?[string]bool, f:?(piff, paff), g:(f:float) ) -> ()\n";

        assert_se(varlink_idl_parse(text, NULL, NULL, &parsed) >= 0);
        test_parse_format_one(parsed);

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

        assert_se(json_build(&v, JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR("a", JSON_BUILD_STRING("x")),
                                             JSON_BUILD_PAIR("b", JSON_BUILD_UNSIGNED(44)),
                                             JSON_BUILD_PAIR("d", JSON_BUILD_ARRAY(JSON_BUILD_UNSIGNED(5), JSON_BUILD_UNSIGNED(7), JSON_BUILD_UNSIGNED(107))),
                                             JSON_BUILD_PAIR("g", JSON_BUILD_OBJECT(JSON_BUILD_PAIR("f", JSON_BUILD_REAL(0.5f)))))) >= 0);

        json_variant_dump(v, JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO, stdout, NULL);

        const VarlinkSymbol* symbol = ASSERT_PTR(varlink_idl_find_symbol(parsed, VARLINK_METHOD, "Mymethod"));

        assert_se(varlink_idl_validate_method_call(symbol, v, NULL) >= 0);
}

static int test_recursive_one(unsigned depth) {
        _cleanup_(varlink_interface_freep) VarlinkInterface *parsed = NULL;
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

static int test_method(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        JsonVariant *foo = json_variant_by_key(parameters, "foo"), *bar = json_variant_by_key(parameters, "bar");

        return varlink_replyb(link,
                              JSON_BUILD_OBJECT(
                                              JSON_BUILD_PAIR_UNSIGNED("waldo", json_variant_unsigned(foo) * json_variant_unsigned(bar)),
                                              JSON_BUILD_PAIR_UNSIGNED("quux", json_variant_unsigned(foo) + json_variant_unsigned(bar))));
}

static int done_method(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata) {
        assert_se(sd_event_exit(varlink_get_event(link), 0) >= 0);
        return 0;
}

static VARLINK_DEFINE_METHOD(
                TestMethod,
                VARLINK_DEFINE_INPUT(foo, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(bar, VARLINK_INT, 0),
                VARLINK_DEFINE_INPUT(optional, VARLINK_STRING, VARLINK_NULLABLE),
                VARLINK_DEFINE_OUTPUT(waldo, VARLINK_INT, 0),
                VARLINK_DEFINE_OUTPUT(quux, VARLINK_INT, 0));

static VARLINK_DEFINE_METHOD(Done);

static VARLINK_DEFINE_INTERFACE(
                xyz,
                "xyz",
                &vl_method_TestMethod,
                &vl_method_Done);


static void* server_thread(void *userdata) {
        _cleanup_(varlink_server_unrefp) VarlinkServer *server = NULL;
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;

        assert_se(varlink_server_new(&server, 0) >= 0);
        assert_se(varlink_server_add_interface(server, &vl_interface_xyz) >= 0);
        assert_se(varlink_server_bind_method(server, "xyz.TestMethod", test_method) >= 0);
        assert_se(varlink_server_bind_method(server, "xyz.Done", done_method) >= 0);

        assert_se(sd_event_new(&event) >= 0);
        assert_se(varlink_server_attach_event(server, event, 0) >= 0);

        assert_se(varlink_server_add_connection(server, PTR_TO_FD(userdata), NULL) >= 0);

        assert_se(sd_event_loop(event) >= 0);
        return NULL;
}

TEST(validate_method_call) {
        _cleanup_close_pair_ int fd[2] = EBADF_PAIR;
        _cleanup_(varlink_unrefp) Varlink *v = NULL;
        pthread_t t;

        assert_se(socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, fd) >= 0);
        assert_se(pthread_create(&t, NULL, server_thread, FD_TO_PTR(TAKE_FD(fd[1]))) == 0);
        assert_se(varlink_connect_fd(&v, TAKE_FD(fd[0])) >= 0);

        JsonVariant *reply = NULL;
        const char *error_id = NULL;
        assert_se(varlink_callb(v, "xyz.TestMethod", &reply, &error_id, NULL,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_UNSIGNED("foo", 8),
                                                JSON_BUILD_PAIR_UNSIGNED("bar", 9))) >= 0);

        _cleanup_(json_variant_unrefp) JsonVariant *expected_reply = NULL;
        assert_se(json_build(&expected_reply,
                             JSON_BUILD_OBJECT(
                                             JSON_BUILD_PAIR_UNSIGNED("waldo", 8*9),
                                             JSON_BUILD_PAIR_UNSIGNED("quux", 8+9))) >= 0);

        assert_se(!error_id);

        json_variant_dump(reply, JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO, NULL, NULL);
        json_variant_dump(expected_reply, JSON_FORMAT_PRETTY_AUTO|JSON_FORMAT_COLOR_AUTO, NULL, NULL);
        assert_se(json_variant_equal(reply, expected_reply));

        assert_se(varlink_callb(v, "xyz.TestMethod", &reply, &error_id, NULL,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_UNSIGNED("foo", 9),
                                                JSON_BUILD_PAIR_UNSIGNED("bar", 8),
                                                JSON_BUILD_PAIR_STRING("optional", "pfft"))) >= 0);

        assert_se(!error_id);
        assert_se(json_variant_equal(reply, expected_reply));

        assert_se(varlink_callb(v, "xyz.TestMethod", &reply, &error_id, NULL,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_UNSIGNED("foo", 8),
                                                JSON_BUILD_PAIR_UNSIGNED("bar", 9),
                                                JSON_BUILD_PAIR_STRING("zzz", "pfft"))) >= 0);
        assert_se(streq_ptr(error_id, VARLINK_ERROR_INVALID_PARAMETER));

        assert_se(varlink_callb(v, "xyz.TestMethod", &reply, &error_id, NULL,
                                JSON_BUILD_OBJECT(
                                                JSON_BUILD_PAIR_STRING("foo", "wuff"),
                                                JSON_BUILD_PAIR_UNSIGNED("bar", 9))) >= 0);
        assert_se(streq_ptr(error_id, VARLINK_ERROR_INVALID_PARAMETER));

        assert_se(varlink_send(v, "xyz.Done", NULL) >= 0);
        assert_se(varlink_flush(v) >= 0);
        assert_se(pthread_join(t, NULL) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
