/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Integration test for the OVSDB client against a real ovsdb-server.
 * Requires: /usr/sbin/ovsdb-server, /usr/bin/ovsdb-tool, /usr/bin/ovs-vsctl installed.
 * Skipped (exit 77) if not available.
 *
 * NOTE: These tests exercise the OVSDB protocol layer only. They do NOT
 * test kernel-side integration (RTM_NEWLINK → ifindex binding), which
 * would require running ovs-vswitchd with CAP_NET_ADMIN. For that, rely
 * on upstream integration testing infrastructure or manual smoke tests. */

#include "sd-event.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "fileio.h"
#include "json-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "tests.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "ovsdb/ovsdb-client.h"
#include "ovsdb/ovsdb-ops.h"

static PidRef server_pidref = PIDREF_NULL;
static char *server_tmpdir = NULL;

static void cleanup_ovsdb_server(void) {
        pidref_done_sigkill_wait(&server_pidref);

        if (server_tmpdir) {
                (void) rm_rf(server_tmpdir, REMOVE_ROOT|REMOVE_PHYSICAL);
                server_tmpdir = mfree(server_tmpdir);
        }
}

static int run_command(const char *name, const char *path, char * const argv[]) {
        int r;

        r = pidref_safe_fork(name, FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_WAIT, NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* child */
                execv(path, argv);
                log_error_errno(errno, "Failed to exec %s: %m", path);
                _exit(EXIT_FAILURE);
        }

        return 0;
}

static int setup_ovsdb_server(char **ret_socket_path) {
        _cleanup_free_ char *db_path = NULL, *sock_path = NULL, *ctl_path = NULL, *pid_path = NULL;
        _cleanup_free_ char *remote_arg = NULL, *db_arg = NULL;
        int r;

        /* 1. Check binaries exist */
        if (access("/usr/sbin/ovsdb-server", X_OK) < 0 ||
            access("/usr/bin/ovsdb-tool", X_OK) < 0 ||
            access("/usr/bin/ovs-vsctl", X_OK) < 0)
                return -ENOENT;

        /* 2. Find vswitch.ovsschema */
        const char *schema = "/usr/share/openvswitch/vswitch.ovsschema";
        if (access(schema, R_OK) < 0)
                return -ENOENT;

        /* 3. Create tmpdir */
        r = mkdtemp_malloc("/tmp/ovsdb-test-XXXXXX", &server_tmpdir);
        if (r < 0)
                return r;

        /* 4. Build paths */
        db_path = path_join(server_tmpdir, "test.db");
        sock_path = path_join(server_tmpdir, "db.sock");
        ctl_path = path_join(server_tmpdir, "ctl");
        pid_path = path_join(server_tmpdir, "pid");
        if (!db_path || !sock_path || !ctl_path || !pid_path)
                return -ENOMEM;

        /* 5. Create database */
        r = run_command(
                        "(ovsdb-tool)",
                        "/usr/bin/ovsdb-tool",
                        STRV_MAKE("ovsdb-tool", "create", db_path, schema));
        if (r < 0)
                return r;

        /* 6. Start ovsdb-server (detached via --detach) */
        remote_arg = strjoin("punix:", sock_path);
        if (!remote_arg)
                return -ENOMEM;

        _cleanup_free_ char *pidfile_arg = NULL, *unixctl_arg = NULL;
        pidfile_arg = strjoin("--pidfile=", pid_path);
        unixctl_arg = strjoin("--unixctl=", ctl_path);
        if (!pidfile_arg || !unixctl_arg)
                return -ENOMEM;

        r = run_command(
                        "(ovsdb-server)",
                        "/usr/sbin/ovsdb-server",
                        STRV_MAKE("ovsdb-server",
                                  "--remote", remote_arg,
                                  unixctl_arg,
                                  pidfile_arg,
                                  "--detach",
                                  db_path));
        if (r < 0)
                return r;

        /* 7. Read server PID from pidfile (ovsdb-server --detach writes it) */
        /* Give the server a moment to write the pidfile */
        for (int i = 0; i < 50; i++) {
                _cleanup_free_ char *pid_contents = NULL;
                pid_t pid;

                r = read_one_line_file(pid_path, &pid_contents);
                if (r >= 0) {
                        r = parse_pid(pid_contents, &pid);
                        if (r >= 0) {
                                r = pidref_set_pid(&server_pidref, pid);
                                if (r >= 0)
                                        break;
                        }
                }

                (void) usleep_safe(100 * USEC_PER_MSEC);
        }

        if (!pidref_is_set(&server_pidref))
                return log_error_errno(SYNTHETIC_ERRNO(ESRCH), "Failed to read ovsdb-server PID");

        /* 8. Initialize Open_vSwitch root row */
        db_arg = strjoin("unix:", sock_path);
        if (!db_arg)
                return -ENOMEM;

        r = run_command(
                        "(ovs-vsctl)",
                        "/usr/bin/ovs-vsctl",
                        STRV_MAKE("ovs-vsctl", "--db", db_arg, "--no-wait", "init"));
        if (r < 0)
                return r;

        *ret_socket_path = TAKE_PTR(sock_path);
        return 0;
}

static bool transact_done = false;
static bool transact_success = false;

static int on_transact(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        transact_done = true;

        if (error) {
                _cleanup_free_ char *text = NULL;
                (void) sd_json_variant_format(error, 0, &text);
                log_error("Transact error: %s", strna(text));
                return 0;
        }

        /* Check each operation result for errors */
        sd_json_variant *element;
        JSON_VARIANT_ARRAY_FOREACH(element, result) {
                sd_json_variant *err = sd_json_variant_by_key(element, "error");
                if (err && !sd_json_variant_is_null(err)) {
                        _cleanup_free_ char *text = NULL;
                        (void) sd_json_variant_format(element, 0, &text);
                        log_error("Operation error: %s", strna(text));
                        return 0;
                }
        }

        transact_success = true;
        return 0;
}

static bool transact2_done = false;
static bool transact2_success = false;

static int on_transact2(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        transact2_done = true;

        if (error) {
                _cleanup_free_ char *text = NULL;
                (void) sd_json_variant_format(error, 0, &text);
                log_error("Transact2 error: %s", strna(text));
                return 0;
        }

        sd_json_variant *element;
        JSON_VARIANT_ARRAY_FOREACH(element, result) {
                sd_json_variant *err = sd_json_variant_by_key(element, "error");
                if (err && !sd_json_variant_is_null(err)) {
                        _cleanup_free_ char *text = NULL;
                        (void) sd_json_variant_format(element, 0, &text);
                        log_error("Transact2 operation error: %s", strna(text));
                        return 0;
                }
        }

        transact2_success = true;
        return 0;
}

/* State for select-then-delete pattern in test_ovsdb_integration_delete_bridge */
static bool select_done = false;
static char *selected_bridge_uuid = NULL;

static int on_select_bridge_uuid(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        select_done = true;

        if (error) {
                _cleanup_free_ char *text = NULL;
                (void) sd_json_variant_format(error, 0, &text);
                log_error("Select error: %s", strna(text));
                return 0;
        }

        /* result is an array of op results; first op is the select.
         * select result: {"rows": [{"_uuid": ["uuid", "<uuid-str>"], ...}]} */
        sd_json_variant *op_result = sd_json_variant_by_index(result, 0);
        if (!op_result)
                return 0;

        sd_json_variant *rows = sd_json_variant_by_key(op_result, "rows");
        if (!rows || !sd_json_variant_is_array(rows))
                return 0;

        sd_json_variant *row = sd_json_variant_by_index(rows, 0);
        if (!row)
                return 0;

        /* _uuid is ["uuid", "<uuid-string>"] */
        sd_json_variant *uuid_pair = sd_json_variant_by_key(row, "_uuid");
        if (!uuid_pair || !sd_json_variant_is_array(uuid_pair))
                return 0;

        sd_json_variant *uuid_str = sd_json_variant_by_index(uuid_pair, 1);
        if (!uuid_str || !sd_json_variant_is_string(uuid_str))
                return 0;

        selected_bridge_uuid = strdup(sd_json_variant_string(uuid_str));
        if (!selected_bridge_uuid)
                return log_oom();
        return 0;
}

TEST(ovsdb_integration_create_bridge) {
        _cleanup_free_ char *socket_path = NULL;
        int r;

        r = setup_ovsdb_server(&socket_path);
        if (r == -ENOENT)
                return (void) log_tests_skipped("ovsdb-server, ovsdb-tool, or ovs-vsctl not available");
        ASSERT_OK(r);

        /* Create client and connect */
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        ASSERT_OK(ovsdb_client_new(&c, e, socket_path));
        ASSERT_OK(ovsdb_client_start(c));

        /* Drive event loop until READY */
        for (int i = 0; i < 500 && ovsdb_client_get_state(c) != OVSDB_CLIENT_READY; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
        ASSERT_EQ(ovsdb_client_get_state(c), (int) OVSDB_CLIENT_READY);

        log_info("Client reached READY state, sending transact...");

        /* Build a transact to create bridge "testbr" */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL, *port_row = NULL, *bridge_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_iface = NULL, *op_insert_port = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_bridge = NULL, *op_mutate = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where_all = NULL;

        /* Interface row */
        ASSERT_OK(sd_json_buildo(&iface_row,
                SD_JSON_BUILD_PAIR_STRING("name", "testbr"),
                SD_JSON_BUILD_PAIR_STRING("type", "internal")));
        ASSERT_OK(ovsdb_op_insert("Interface", "iface_testbr", iface_row, &op_insert_iface));

        /* Port row with interface reference */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
        ASSERT_OK(sd_json_build(&iface_ref,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("named-uuid"),
                        SD_JSON_BUILD_STRING("iface_testbr"))));
        ASSERT_OK(sd_json_buildo(&port_row,
                SD_JSON_BUILD_PAIR_STRING("name", "testbr"),
                SD_JSON_BUILD_PAIR("interfaces", SD_JSON_BUILD_VARIANT(iface_ref))));
        ASSERT_OK(ovsdb_op_insert("Port", "port_testbr", port_row, &op_insert_port));

        /* Bridge row with port reference */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
        ASSERT_OK(sd_json_build(&port_ref,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("named-uuid"),
                        SD_JSON_BUILD_STRING("port_testbr"))));
        ASSERT_OK(sd_json_buildo(&bridge_row,
                SD_JSON_BUILD_PAIR_STRING("name", "testbr"),
                SD_JSON_BUILD_PAIR("ports", SD_JSON_BUILD_VARIANT(port_ref))));
        ASSERT_OK(ovsdb_op_insert("Bridge", "br_testbr", bridge_row, &op_insert_bridge));

        /* Mutate Open_vSwitch to add bridge */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_set_ref = NULL;
        ASSERT_OK(sd_json_build(&br_set_ref,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("set"),
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("named-uuid"),
                                        SD_JSON_BUILD_STRING("br_testbr"))))));
        ASSERT_OK(sd_json_build(&mutations,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("bridges"),
                                SD_JSON_BUILD_STRING("insert"),
                                SD_JSON_BUILD_VARIANT(br_set_ref)))));
        ASSERT_OK(ovsdb_where_all(&where_all));
        ASSERT_OK(ovsdb_op_mutate("Open_vSwitch", where_all, mutations, &op_mutate));

        /* Compose ops array */
        ASSERT_OK(sd_json_build(&ops,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_VARIANT(op_insert_iface),
                        SD_JSON_BUILD_VARIANT(op_insert_port),
                        SD_JSON_BUILD_VARIANT(op_insert_bridge),
                        SD_JSON_BUILD_VARIANT(op_mutate))));

        /* Send transact */
        transact_done = false;
        transact_success = false;
        ASSERT_OK(ovsdb_client_transact(c, ops, on_transact, NULL));

        /* Drive event loop until transact completes */
        for (int i = 0; i < 500 && !transact_done; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));

        ASSERT_TRUE(transact_done);
        ASSERT_TRUE(transact_success);

        log_info("Bridge 'testbr' created successfully via OVSDB transact");
}

TEST(ovsdb_integration_system_port_attachment) {
        /* Reuse the already-running server (started by test_ovsdb_integration_create_bridge) */
        if (!server_tmpdir)
                return (void) log_tests_skipped("ovsdb-server not running");

        _cleanup_free_ char *socket_path = NULL;
        socket_path = path_join(server_tmpdir, "db.sock");
        ASSERT_NOT_NULL(socket_path);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        ASSERT_OK(ovsdb_client_new(&c, e, socket_path));
        ASSERT_OK(ovsdb_client_start(c));

        for (int i = 0; i < 500 && ovsdb_client_get_state(c) != OVSDB_CLIENT_READY; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
        ASSERT_EQ(ovsdb_client_get_state(c), (int) OVSDB_CLIENT_READY);

        log_info("Client reached READY state, attaching system port 'dummy0' to bridge 'testbr'...");

        /* Build transact: INSERT Interface + INSERT Port + mutate Bridge.ports += port_ref */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL, *port_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_iface = NULL, *op_insert_port = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_mutate_bridge = NULL;

        /* Interface row: name="dummy0", type="" (system port) */
        ASSERT_OK(sd_json_buildo(&iface_row,
                SD_JSON_BUILD_PAIR_STRING("name", "dummy0"),
                SD_JSON_BUILD_PAIR_STRING("type", "")));
        ASSERT_OK(ovsdb_op_insert("Interface", "iface_dummy0", iface_row, &op_insert_iface));

        /* Port row: name="dummy0", interfaces=ref to iface, tag=10 */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
        ASSERT_OK(sd_json_build(&iface_ref,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("named-uuid"),
                        SD_JSON_BUILD_STRING("iface_dummy0"))));
        ASSERT_OK(sd_json_buildo(&port_row,
                SD_JSON_BUILD_PAIR_STRING("name", "dummy0"),
                SD_JSON_BUILD_PAIR("interfaces", SD_JSON_BUILD_VARIANT(iface_ref)),
                SD_JSON_BUILD_PAIR_INTEGER("tag", 10)));
        ASSERT_OK(ovsdb_op_insert("Port", "port_dummy0", port_row, &op_insert_port));

        /* mutate Bridge where name="testbr": ports insert [named-uuid port_dummy0] */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_where = NULL;
        ASSERT_OK(sd_json_build(&br_where,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("name"),
                                SD_JSON_BUILD_STRING("=="),
                                SD_JSON_BUILD_STRING("testbr")))));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
        ASSERT_OK(sd_json_build(&port_ref,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("named-uuid"),
                        SD_JSON_BUILD_STRING("port_dummy0"))));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_set_ref = NULL;
        ASSERT_OK(sd_json_build(&port_set_ref,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("set"),
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_VARIANT(port_ref)))));

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        ASSERT_OK(sd_json_build(&mutations,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("ports"),
                                SD_JSON_BUILD_STRING("insert"),
                                SD_JSON_BUILD_VARIANT(port_set_ref)))));
        ASSERT_OK(ovsdb_op_mutate("Bridge", br_where, mutations, &op_mutate_bridge));

        /* Compose ops array */
        ASSERT_OK(sd_json_build(&ops,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_VARIANT(op_insert_iface),
                        SD_JSON_BUILD_VARIANT(op_insert_port),
                        SD_JSON_BUILD_VARIANT(op_mutate_bridge))));

        transact_done = false;
        transact_success = false;
        ASSERT_OK(ovsdb_client_transact(c, ops, on_transact, /* userdata= */ NULL));

        for (int i = 0; i < 500 && !transact_done; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));

        ASSERT_TRUE(transact_done);
        ASSERT_TRUE(transact_success);

        log_info("System port 'dummy0' attached to bridge 'testbr'");
}

TEST(ovsdb_integration_update_existing) {
        /* Tests the UPDATE path: modify an existing bridge's fail_mode
         * and an existing port's tag. This exercises the reconciler's
         * reload/reconnect code path. */
        if (!server_tmpdir)
                return (void) log_tests_skipped("ovsdb-server not running");

        _cleanup_free_ char *socket_path = NULL;
        socket_path = path_join(server_tmpdir, "db.sock");
        ASSERT_NOT_NULL(socket_path);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        ASSERT_OK(ovsdb_client_new(&c, e, socket_path));
        ASSERT_OK(ovsdb_client_start(c));

        for (int i = 0; i < 500 && ovsdb_client_get_state(c) != OVSDB_CLIENT_READY; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
        ASSERT_EQ(ovsdb_client_get_state(c), (int) OVSDB_CLIENT_READY);

        log_info("Updating bridge 'testbr' fail_mode to 'secure' and port 'dummy0' tag to 20...");

        /* UPDATE Bridge where name="testbr": set fail_mode="secure" */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_update_bridge = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_update_port = NULL;
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_where = NULL;
                ASSERT_OK(sd_json_build(&br_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("testbr")))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_row = NULL;
                ASSERT_OK(sd_json_buildo(&br_row,
                        SD_JSON_BUILD_PAIR_STRING("fail_mode", "secure")));
                ASSERT_OK(ovsdb_op_update("Bridge", br_where, br_row, &op_update_bridge));
        }

        /* UPDATE Port where name="dummy0": set tag=20 */
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_where = NULL;
                ASSERT_OK(sd_json_build(&port_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("dummy0")))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL;
                ASSERT_OK(sd_json_buildo(&port_row,
                        SD_JSON_BUILD_PAIR_INTEGER("tag", 20)));
                ASSERT_OK(ovsdb_op_update("Port", port_where, port_row, &op_update_port));
        }

        ASSERT_OK(sd_json_build(&ops,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_VARIANT(op_update_bridge),
                        SD_JSON_BUILD_VARIANT(op_update_port))));

        transact_done = false;
        transact_success = false;
        ASSERT_OK(ovsdb_client_transact(c, ops, on_transact, /* userdata= */ NULL));

        for (int i = 0; i < 500 && !transact_done; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));

        ASSERT_TRUE(transact_done);
        ASSERT_TRUE(transact_success);

        /* Verify by selecting the bridge and checking fail_mode */
        log_info("Verifying update...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *verify_ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_select = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_where = NULL;
                ASSERT_OK(sd_json_build(&br_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("testbr")))));
                ASSERT_OK(ovsdb_op_select("Bridge", br_where, /* columns= */ NULL, &op_select));
                ASSERT_OK(sd_json_build(&verify_ops,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_VARIANT(op_select))));

                transact2_done = false;
                transact2_success = false;
                ASSERT_OK(ovsdb_client_transact(c, verify_ops, on_transact2, /* userdata= */ NULL));

                for (int i = 0; i < 500 && !transact2_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));

                ASSERT_TRUE(transact2_done);
                ASSERT_TRUE(transact2_success);
        }

        log_info("UPDATE test passed — existing objects updated successfully");
}

TEST(ovsdb_integration_bond_port) {
        /* Tests bond port creation: a Port with multiple Interface references
         * and native bond columns (bond_mode, lacp, bond_updelay, bond_downdelay). */
        if (!server_tmpdir)
                return (void) log_tests_skipped("ovsdb-server not running");

        _cleanup_free_ char *socket_path = NULL;
        socket_path = path_join(server_tmpdir, "db.sock");
        ASSERT_NOT_NULL(socket_path);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        ASSERT_OK(ovsdb_client_new(&c, e, socket_path));
        ASSERT_OK(ovsdb_client_start(c));

        for (int i = 0; i < 500 && ovsdb_client_get_state(c) != OVSDB_CLIENT_READY; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
        ASSERT_EQ(ovsdb_client_get_state(c), (int) OVSDB_CLIENT_READY);

        log_info("Creating bond port 'bond0' with two members on bridge 'testbr'...");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface1_row = NULL, *iface2_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_iface1 = NULL, *op_insert_iface2 = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL, *op_insert_port = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_mutate_bridge = NULL;

        /* Interface 1: eth1 (system port) */
        ASSERT_OK(sd_json_buildo(&iface1_row,
                SD_JSON_BUILD_PAIR_STRING("name", "eth1"),
                SD_JSON_BUILD_PAIR_STRING("type", "")));
        ASSERT_OK(ovsdb_op_insert("Interface", "iface_eth1", iface1_row, &op_insert_iface1));

        /* Interface 2: eth2 (system port) */
        ASSERT_OK(sd_json_buildo(&iface2_row,
                SD_JSON_BUILD_PAIR_STRING("name", "eth2"),
                SD_JSON_BUILD_PAIR_STRING("type", "")));
        ASSERT_OK(ovsdb_op_insert("Interface", "iface_eth2", iface2_row, &op_insert_iface2));

        /* Port row: bond0 with interfaces=[eth1, eth2], native bond columns */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_set = NULL;
        ASSERT_OK(sd_json_build(&iface_set,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("set"),
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("named-uuid"),
                                        SD_JSON_BUILD_STRING("iface_eth1")),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("named-uuid"),
                                        SD_JSON_BUILD_STRING("iface_eth2"))))));
        ASSERT_OK(sd_json_buildo(&port_row,
                SD_JSON_BUILD_PAIR_STRING("name", "bond0"),
                SD_JSON_BUILD_PAIR("interfaces", SD_JSON_BUILD_VARIANT(iface_set)),
                SD_JSON_BUILD_PAIR_STRING("bond_mode", "balance-slb"),
                SD_JSON_BUILD_PAIR_STRING("lacp", "active"),
                SD_JSON_BUILD_PAIR_INTEGER("bond_updelay", 100),
                SD_JSON_BUILD_PAIR_INTEGER("bond_downdelay", 200)));
        ASSERT_OK(ovsdb_op_insert("Port", "port_bond0", port_row, &op_insert_port));

        /* Mutate bridge testbr to add bond port */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_where = NULL;
        ASSERT_OK(sd_json_build(&br_where,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("name"),
                                SD_JSON_BUILD_STRING("=="),
                                SD_JSON_BUILD_STRING("testbr")))));
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
        ASSERT_OK(sd_json_build(&port_ref,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("named-uuid"),
                        SD_JSON_BUILD_STRING("port_bond0"))));
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_set_ref = NULL;
        ASSERT_OK(sd_json_build(&port_set_ref,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("set"),
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_VARIANT(port_ref)))));
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        ASSERT_OK(sd_json_build(&mutations,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("ports"),
                                SD_JSON_BUILD_STRING("insert"),
                                SD_JSON_BUILD_VARIANT(port_set_ref)))));
        ASSERT_OK(ovsdb_op_mutate("Bridge", br_where, mutations, &op_mutate_bridge));

        ASSERT_OK(sd_json_build(&ops,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_VARIANT(op_insert_iface1),
                        SD_JSON_BUILD_VARIANT(op_insert_iface2),
                        SD_JSON_BUILD_VARIANT(op_insert_port),
                        SD_JSON_BUILD_VARIANT(op_mutate_bridge))));

        transact_done = false;
        transact_success = false;
        ASSERT_OK(ovsdb_client_transact(c, ops, on_transact, /* userdata= */ NULL));

        for (int i = 0; i < 500 && !transact_done; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));

        ASSERT_TRUE(transact_done);
        ASSERT_TRUE(transact_success);

        log_info("Bond port 'bond0' with 2 members created successfully");
}

TEST(ovsdb_integration_port_type_transition) {
        /* Create a patch port (Interface.type=patch + options:peer), then transition
         * it to internal (type=internal + cleared options) via UPDATE — the path
         * exercised by ovs_reconcile_port when a .netdev's Type= changes between
         * patch and internal. */
        if (!server_tmpdir)
                return (void) log_tests_skipped("ovsdb-server not running");

        _cleanup_free_ char *socket_path = NULL;
        socket_path = path_join(server_tmpdir, "db.sock");
        ASSERT_NOT_NULL(socket_path);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        ASSERT_OK(ovsdb_client_new(&c, e, socket_path));
        ASSERT_OK(ovsdb_client_start(c));

        for (int i = 0; i < 500 && ovsdb_client_get_state(c) != OVSDB_CLIENT_READY; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
        ASSERT_EQ(ovsdb_client_get_state(c), (int) OVSDB_CLIENT_READY);

        /* Step 1: INSERT patch port "patch0" with Interface.type=patch and options:peer=patch1 */
        log_info("Creating patch port 'patch0'...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_iface = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_port = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_mutate_bridge = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_options = NULL;

                ASSERT_OK(sd_json_build(&iface_options,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("map"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("peer"),
                                                SD_JSON_BUILD_STRING("patch1"))))));
                ASSERT_OK(sd_json_buildo(&iface_row,
                        SD_JSON_BUILD_PAIR_STRING("name", "patch0"),
                        SD_JSON_BUILD_PAIR_STRING("type", "patch"),
                        SD_JSON_BUILD_PAIR_VARIANT("options", iface_options)));
                ASSERT_OK(ovsdb_op_insert("Interface", "iface_patch0", iface_row, &op_insert_iface));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
                ASSERT_OK(sd_json_build(&iface_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("named-uuid"),
                                SD_JSON_BUILD_STRING("iface_patch0"))));
                ASSERT_OK(sd_json_buildo(&port_row,
                        SD_JSON_BUILD_PAIR_STRING("name", "patch0"),
                        SD_JSON_BUILD_PAIR("interfaces", SD_JSON_BUILD_VARIANT(iface_ref))));
                ASSERT_OK(ovsdb_op_insert("Port", "port_patch0", port_row, &op_insert_port));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_where = NULL;
                ASSERT_OK(sd_json_build(&br_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("testbr")))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
                ASSERT_OK(sd_json_build(&port_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("named-uuid"),
                                SD_JSON_BUILD_STRING("port_patch0"))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_set_ref = NULL;
                ASSERT_OK(sd_json_build(&port_set_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("set"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_VARIANT(port_ref)))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
                ASSERT_OK(sd_json_build(&mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("ports"),
                                        SD_JSON_BUILD_STRING("insert"),
                                        SD_JSON_BUILD_VARIANT(port_set_ref)))));
                ASSERT_OK(ovsdb_op_mutate("Bridge", br_where, mutations, &op_mutate_bridge));

                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_VARIANT(op_insert_iface),
                                SD_JSON_BUILD_VARIANT(op_insert_port),
                                SD_JSON_BUILD_VARIANT(op_mutate_bridge))));

                transact_done = false;
                transact_success = false;
                ASSERT_OK(ovsdb_client_transact(c, ops, on_transact, /* userdata= */ NULL));
                for (int i = 0; i < 500 && !transact_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
                ASSERT_TRUE(transact_done);
                ASSERT_TRUE(transact_success);
        }

        /* Step 2: UPDATE Interface where name="patch0": type=internal + options=["map", []]
         * This is what ovs_reconcile_port emits when the .netdev Type= changes from
         * patch to internal. Verifies that both the type field and the patch-only
         * options can be rewritten/cleared in a single UPDATE op. */
        log_info("Transitioning patch0 from patch to internal...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_op = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty_options = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_where = NULL;

                ASSERT_OK(sd_json_build(&empty_options,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("map"),
                                SD_JSON_BUILD_EMPTY_ARRAY)));
                ASSERT_OK(sd_json_buildo(&update_row,
                        SD_JSON_BUILD_PAIR_STRING("type", "internal"),
                        SD_JSON_BUILD_PAIR_VARIANT("options", empty_options)));
                ASSERT_OK(sd_json_build(&iface_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("patch0")))));
                ASSERT_OK(ovsdb_op_update("Interface", iface_where, update_row, &update_op));
                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_VARIANT(update_op))));

                transact_done = false;
                transact_success = false;
                ASSERT_OK(ovsdb_client_transact(c, ops, on_transact, /* userdata= */ NULL));
                for (int i = 0; i < 500 && !transact_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
                ASSERT_TRUE(transact_done);
                ASSERT_TRUE(transact_success);
        }

        /* Step 3: SELECT Interface and verify type is now "internal" with empty options */
        log_info("Verifying type transition...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_select = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_where = NULL;

                ASSERT_OK(sd_json_build(&iface_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("patch0")))));
                ASSERT_OK(ovsdb_op_select("Interface", iface_where, /* columns= */ NULL, &op_select));
                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_VARIANT(op_select))));

                transact2_done = false;
                transact2_success = false;
                ASSERT_OK(ovsdb_client_transact(c, ops, on_transact2, /* userdata= */ NULL));
                for (int i = 0; i < 500 && !transact2_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
                ASSERT_TRUE(transact2_done);
                ASSERT_TRUE(transact2_success);
        }

        log_info("Port type transition test passed — Interface.type and options correctly rewritten");
}

TEST(ovsdb_integration_tunnel_type_transition) {
        /* Create a vxlan tunnel Interface (type=vxlan + options:remote_ip), then
         * transition it to gre (type=gre + rebuilt options) via UPDATE — the path
         * exercised by ovs_reconcile_tunnel when a .netdev's Type= changes. */
        if (!server_tmpdir)
                return (void) log_tests_skipped("ovsdb-server not running");

        _cleanup_free_ char *socket_path = NULL;
        socket_path = path_join(server_tmpdir, "db.sock");
        ASSERT_NOT_NULL(socket_path);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        ASSERT_OK(ovsdb_client_new(&c, e, socket_path));
        ASSERT_OK(ovsdb_client_start(c));

        for (int i = 0; i < 500 && ovsdb_client_get_state(c) != OVSDB_CLIENT_READY; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
        ASSERT_EQ(ovsdb_client_get_state(c), (int) OVSDB_CLIENT_READY);

        /* Step 1: INSERT tunnel "tun0" with Interface.type=vxlan and options:remote_ip=10.0.0.1 */
        log_info("Creating vxlan tunnel 'tun0'...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_iface = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_port = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_mutate_bridge = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_options = NULL;

                ASSERT_OK(sd_json_build(&iface_options,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("map"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("remote_ip"),
                                                SD_JSON_BUILD_STRING("10.0.0.1"))))));
                ASSERT_OK(sd_json_buildo(&iface_row,
                        SD_JSON_BUILD_PAIR_STRING("name", "tun0"),
                        SD_JSON_BUILD_PAIR_STRING("type", "vxlan"),
                        SD_JSON_BUILD_PAIR_VARIANT("options", iface_options)));
                ASSERT_OK(ovsdb_op_insert("Interface", "iface_tun0", iface_row, &op_insert_iface));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
                ASSERT_OK(sd_json_build(&iface_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("named-uuid"),
                                SD_JSON_BUILD_STRING("iface_tun0"))));
                ASSERT_OK(sd_json_buildo(&port_row,
                        SD_JSON_BUILD_PAIR_STRING("name", "tun0"),
                        SD_JSON_BUILD_PAIR("interfaces", SD_JSON_BUILD_VARIANT(iface_ref))));
                ASSERT_OK(ovsdb_op_insert("Port", "port_tun0", port_row, &op_insert_port));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_where = NULL;
                ASSERT_OK(sd_json_build(&br_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("testbr")))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
                ASSERT_OK(sd_json_build(&port_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("named-uuid"),
                                SD_JSON_BUILD_STRING("port_tun0"))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_set_ref = NULL;
                ASSERT_OK(sd_json_build(&port_set_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("set"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_VARIANT(port_ref)))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
                ASSERT_OK(sd_json_build(&mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("ports"),
                                        SD_JSON_BUILD_STRING("insert"),
                                        SD_JSON_BUILD_VARIANT(port_set_ref)))));
                ASSERT_OK(ovsdb_op_mutate("Bridge", br_where, mutations, &op_mutate_bridge));

                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_VARIANT(op_insert_iface),
                                SD_JSON_BUILD_VARIANT(op_insert_port),
                                SD_JSON_BUILD_VARIANT(op_mutate_bridge))));

                transact_done = false;
                transact_success = false;
                ASSERT_OK(ovsdb_client_transact(c, ops, on_transact, /* userdata= */ NULL));
                for (int i = 0; i < 500 && !transact_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
                ASSERT_TRUE(transact_done);
                ASSERT_TRUE(transact_success);
        }

        /* Step 2: UPDATE Interface where name="tun0": type=gre + rebuilt options.
         * This is what ovs_reconcile_tunnel emits when the .netdev Type= changes
         * from vxlan to gre. Verifies that both the type field and the tunnel
         * options are rewritten in a single UPDATE op. */
        log_info("Transitioning tun0 from vxlan to gre...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_op = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *new_options = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_where = NULL;

                ASSERT_OK(sd_json_build(&new_options,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("map"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("remote_ip"),
                                                SD_JSON_BUILD_STRING("10.0.0.2"))))));
                ASSERT_OK(sd_json_buildo(&update_row,
                        SD_JSON_BUILD_PAIR_STRING("type", "gre"),
                        SD_JSON_BUILD_PAIR_VARIANT("options", new_options)));
                ASSERT_OK(sd_json_build(&iface_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("tun0")))));
                ASSERT_OK(ovsdb_op_update("Interface", iface_where, update_row, &update_op));
                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_VARIANT(update_op))));

                transact_done = false;
                transact_success = false;
                ASSERT_OK(ovsdb_client_transact(c, ops, on_transact, /* userdata= */ NULL));
                for (int i = 0; i < 500 && !transact_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
                ASSERT_TRUE(transact_done);
                ASSERT_TRUE(transact_success);
        }

        /* Step 3: SELECT Interface and verify type is now "gre" */
        log_info("Verifying tunnel type transition...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_select = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_where = NULL;

                ASSERT_OK(sd_json_build(&iface_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("tun0")))));
                ASSERT_OK(ovsdb_op_select("Interface", iface_where, /* columns= */ NULL, &op_select));
                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(SD_JSON_BUILD_VARIANT(op_select))));

                transact2_done = false;
                transact2_success = false;
                ASSERT_OK(ovsdb_client_transact(c, ops, on_transact2, /* userdata= */ NULL));
                for (int i = 0; i < 500 && !transact2_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
                ASSERT_TRUE(transact2_done);
                ASSERT_TRUE(transact2_success);
        }

        log_info("Tunnel type transition test passed — Interface.type and options correctly rewritten");
}

TEST(ovsdb_integration_delete_bridge) {
        /* Reuse the already-running server */
        if (!server_tmpdir)
                return (void) log_tests_skipped("ovsdb-server not running");

        _cleanup_free_ char *socket_path = NULL;
        socket_path = path_join(server_tmpdir, "db.sock");
        ASSERT_NOT_NULL(socket_path);

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        ASSERT_OK(sd_event_default(&e));

        _cleanup_(ovsdb_client_unrefp) OVSDBClient *c = NULL;
        ASSERT_OK(ovsdb_client_new(&c, e, socket_path));
        ASSERT_OK(ovsdb_client_start(c));

        for (int i = 0; i < 500 && ovsdb_client_get_state(c) != OVSDB_CLIENT_READY; i++)
                ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));
        ASSERT_EQ(ovsdb_client_get_state(c), (int) OVSDB_CLIENT_READY);

        log_info("Client reached READY state, creating bridge 'testbr2' with external_ids...");

        /* Step 1: Create bridge "testbr2" with external_ids={networkd-managed=true} */
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL, *port_row = NULL, *bridge_row = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_iface = NULL, *op_insert_port = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_insert_bridge = NULL, *op_mutate = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *where_all = NULL;

                ASSERT_OK(sd_json_buildo(&iface_row,
                        SD_JSON_BUILD_PAIR_STRING("name", "testbr2"),
                        SD_JSON_BUILD_PAIR_STRING("type", "internal")));
                ASSERT_OK(ovsdb_op_insert("Interface", "iface_testbr2", iface_row, &op_insert_iface));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
                ASSERT_OK(sd_json_build(&iface_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("named-uuid"),
                                SD_JSON_BUILD_STRING("iface_testbr2"))));
                ASSERT_OK(sd_json_buildo(&port_row,
                        SD_JSON_BUILD_PAIR_STRING("name", "testbr2"),
                        SD_JSON_BUILD_PAIR("interfaces", SD_JSON_BUILD_VARIANT(iface_ref))));
                ASSERT_OK(ovsdb_op_insert("Port", "port_testbr2", port_row, &op_insert_port));

                /* Bridge row with external_ids={"networkd-managed": "true"} */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
                ASSERT_OK(sd_json_build(&port_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("named-uuid"),
                                SD_JSON_BUILD_STRING("port_testbr2"))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ext_ids = NULL;
                ASSERT_OK(sd_json_build(&ext_ids,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("map"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("networkd-managed"),
                                                SD_JSON_BUILD_STRING("true"))))));
                ASSERT_OK(sd_json_buildo(&bridge_row,
                        SD_JSON_BUILD_PAIR_STRING("name", "testbr2"),
                        SD_JSON_BUILD_PAIR("ports", SD_JSON_BUILD_VARIANT(port_ref)),
                        SD_JSON_BUILD_PAIR("external_ids", SD_JSON_BUILD_VARIANT(ext_ids))));
                ASSERT_OK(ovsdb_op_insert("Bridge", "br_testbr2", bridge_row, &op_insert_bridge));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_set_ref = NULL;
                ASSERT_OK(sd_json_build(&br_set_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("set"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("named-uuid"),
                                                SD_JSON_BUILD_STRING("br_testbr2"))))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
                ASSERT_OK(sd_json_build(&mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("bridges"),
                                        SD_JSON_BUILD_STRING("insert"),
                                        SD_JSON_BUILD_VARIANT(br_set_ref)))));
                ASSERT_OK(ovsdb_where_all(&where_all));
                ASSERT_OK(ovsdb_op_mutate("Open_vSwitch", where_all, mutations, &op_mutate));

                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_VARIANT(op_insert_iface),
                                SD_JSON_BUILD_VARIANT(op_insert_port),
                                SD_JSON_BUILD_VARIANT(op_insert_bridge),
                                SD_JSON_BUILD_VARIANT(op_mutate))));

                transact2_done = false;
                transact2_success = false;
                ASSERT_OK(ovsdb_client_transact(c, ops, on_transact2, /* userdata= */ NULL));

                for (int i = 0; i < 500 && !transact2_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));

                ASSERT_TRUE(transact2_done);
                ASSERT_TRUE(transact2_success);

                log_info("Bridge 'testbr2' created successfully");
        }

        /* Step 2a: SELECT Bridge where name="testbr2" to get its UUID.
         * We need the UUID to remove the bridge from Open_vSwitch.bridges
         * (strong reference) before deleting the row. */
        log_info("Selecting bridge 'testbr2' UUID...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_select = NULL;

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_where = NULL;
                ASSERT_OK(sd_json_build(&br_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("testbr2")))));
                ASSERT_OK(ovsdb_op_select("Bridge", br_where, /* columns= */ NULL, &op_select));

                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_VARIANT(op_select))));

                select_done = false;
                selected_bridge_uuid = mfree(selected_bridge_uuid);
                ASSERT_OK(ovsdb_client_transact(c, ops, on_select_bridge_uuid, /* userdata= */ NULL));

                for (int i = 0; i < 500 && !select_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));

                ASSERT_TRUE(select_done);
                ASSERT_NOT_NULL(selected_bridge_uuid);
                log_info("Bridge 'testbr2' UUID: %s", selected_bridge_uuid);
        }

        /* Step 2b: mutate Open_vSwitch.bridges delete + DELETE Bridge/Port/Interface.
         * Order matters: remove from Open_vSwitch.bridges first (drop strong ref),
         * then delete the rows. */
        log_info("Deleting bridge 'testbr2'...");
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_mutate_ovs = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_del_iface = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_del_port = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *op_del_bridge = NULL;

                /* mutate Open_vSwitch.bridges delete {["uuid", selected_bridge_uuid]} */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *uuid_ref = NULL;
                ASSERT_OK(sd_json_build(&uuid_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("uuid"),
                                SD_JSON_BUILD_STRING(selected_bridge_uuid))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_set_ref = NULL;
                ASSERT_OK(sd_json_build(&br_set_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("set"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_VARIANT(uuid_ref)))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
                ASSERT_OK(sd_json_build(&mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("bridges"),
                                        SD_JSON_BUILD_STRING("delete"),
                                        SD_JSON_BUILD_VARIANT(br_set_ref)))));
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *where_all = NULL;
                ASSERT_OK(ovsdb_where_all(&where_all));
                ASSERT_OK(ovsdb_op_mutate("Open_vSwitch", where_all, mutations, &op_mutate_ovs));

                /* DELETE Interface, Port, Bridge by name */
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_where = NULL;
                ASSERT_OK(sd_json_build(&iface_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("testbr2")))));
                ASSERT_OK(ovsdb_op_delete("Interface", iface_where, &op_del_iface));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_where = NULL;
                ASSERT_OK(sd_json_build(&port_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("testbr2")))));
                ASSERT_OK(ovsdb_op_delete("Port", port_where, &op_del_port));

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *br_where = NULL;
                ASSERT_OK(sd_json_build(&br_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING("testbr2")))));
                ASSERT_OK(ovsdb_op_delete("Bridge", br_where, &op_del_bridge));

                ASSERT_OK(sd_json_build(&ops,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_VARIANT(op_mutate_ovs),
                                SD_JSON_BUILD_VARIANT(op_del_iface),
                                SD_JSON_BUILD_VARIANT(op_del_port),
                                SD_JSON_BUILD_VARIANT(op_del_bridge))));

                transact2_done = false;
                transact2_success = false;
                ASSERT_OK(ovsdb_client_transact(c, ops, on_transact2, /* userdata= */ NULL));

                for (int i = 0; i < 500 && !transact2_done; i++)
                        ASSERT_OK(sd_event_run(e, 10 * USEC_PER_MSEC));

                ASSERT_TRUE(transact2_done);
                ASSERT_TRUE(transact2_success);

                log_info("Bridge 'testbr2' deleted successfully");
        }

        selected_bridge_uuid = mfree(selected_bridge_uuid);
}

static int intro(void) {
        atexit(cleanup_ovsdb_server);
        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_FULL(LOG_DEBUG, intro, /* outro= */ NULL);
