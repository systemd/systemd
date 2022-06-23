/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>

#include "bus-address.h"
#include "bus-internal.h"
#include "env-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "string-util.h"
#include "user-util.h"

char* bus_address_escape(const char *v) {
        const char *a;
        char *r, *b;

        r = new(char, strlen(v)*3+1);
        if (!r)
                return NULL;

        for (a = v, b = r; *a; a++) {

                if ((*a >= '0' && *a <= '9') ||
                    (*a >= 'a' && *a <= 'z') ||
                    (*a >= 'A' && *a <= 'Z') ||
                    strchr("_-/.", *a))
                        *(b++) = *a;
                else {
                        *(b++) = '%';
                        *(b++) = hexchar(*a >> 4);
                        *(b++) = hexchar(*a & 0xF);
                }
        }

        *b = 0;
        return r;
}

int bus_set_address_system(sd_bus *b) {
        const char *e;
        int r;

        assert(b);

        e = secure_getenv("DBUS_SYSTEM_BUS_ADDRESS");

        r = sd_bus_set_address(b, e ?: DEFAULT_SYSTEM_BUS_ADDRESS);
        if (r >= 0)
                b->is_system = true;
        return r;
}

int bus_set_address_machine(sd_bus *b, bool user, const char *machine) {
        _cleanup_free_ char *a = NULL;
        const char *rhs;

        assert(b);
        assert(machine);

        rhs = strchr(machine, '@');
        if (rhs || user) {
                _cleanup_free_ char *u = NULL, *eu = NULL, *erhs = NULL;

                /* If there's an "@" in the container specification, we'll connect as a user specified at its
                 * left hand side, which is useful in combination with user=true. This isn't as trivial as it
                 * might sound: it's not sufficient to enter the container and connect to some socket there,
                 * since the --user socket path depends on $XDG_RUNTIME_DIR which is set via PAM. Thus, to be
                 * able to connect, we need to have a PAM session. Our way out?  We use systemd-run to get
                 * into the container and acquire a PAM session there, and then invoke systemd-stdio-bridge
                 * in it, which propagates the bus transport to us. */

                if (rhs) {
                        if (rhs > machine)
                                u = strndup(machine, rhs - machine);
                        else
                                u = getusername_malloc(); /* Empty user name, let's use the local one */
                        if (!u)
                                return -ENOMEM;

                        eu = bus_address_escape(u);
                        if (!eu)
                                return -ENOMEM;

                        rhs++;
                } else {
                        /* No "@" specified but we shall connect to the user instance? Then assume root (and
                         * not a user named identically to the calling one). This means:
                         *
                         *     --machine=foobar --user    → connect to user bus of root user in container "foobar"
                         *     --machine=@foobar --user   → connect to user bus of user named like
                         *                                  the calling user in container "foobar"
                         *
                         * Why? so that behaviour for "--machine=foobar --system" is roughly similar to
                         * "--machine=foobar --user": both times we unconditionally connect as root user
                         * regardless what the calling user is. */

                        rhs = machine;
                }

                if (!isempty(rhs)) {
                        erhs = bus_address_escape(rhs);
                        if (!erhs)
                                return -ENOMEM;
                }

                /* systemd-run -M… -PGq --wait -pUser=… -pPAMName=login systemd-stdio-bridge */

                a = strjoin("unixexec:path=systemd-run,"
                            "argv1=-M", erhs ?: ".host", ","
                            "argv2=-PGq,"
                            "argv3=--wait,"
                            "argv4=-pUser%3d", eu ?: "root", ",",
                            "argv5=-pPAMName%3dlogin,"
                            "argv6=systemd-stdio-bridge");
                if (!a)
                        return -ENOMEM;

                if (user) {
                        /* Ideally we'd use the "--user" switch to systemd-stdio-bridge here, but it's only
                         * available in recent systemd versions. Using the "-p" switch with the explicit path
                         * is a working alternative, and is compatible with older versions, hence that's what
                         * we use here. */
                        if (!strextend(&a, ",argv7=-punix:path%3d%24%7bXDG_RUNTIME_DIR%7d/bus"))
                                return -ENOMEM;
                }
        } else {
                _cleanup_free_ char *e = NULL;

                /* Just a container name, we can go the simple way, and just join the container, and connect
                 * to the well-known path of the system bus there. */

                e = bus_address_escape(machine);
                if (!e)
                        return -ENOMEM;

                a = strjoin("x-machine-unix:machine=", e);
                if (!a)
                        return -ENOMEM;
        }

        return free_and_replace(b->address, a);
}

int bus_set_address_user(sd_bus *b) {
        const char *a;
        _cleanup_free_ char *_a = NULL;
        int r;

        assert(b);

        a = secure_getenv("DBUS_SESSION_BUS_ADDRESS");
        if (!a) {
                const char *e;
                _cleanup_free_ char *ee = NULL;

                e = secure_getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                                               "sd-bus: $XDG_RUNTIME_DIR not set, cannot connect to user bus.");

                ee = bus_address_escape(e);
                if (!ee)
                        return -ENOMEM;

                if (asprintf(&_a, DEFAULT_USER_BUS_ADDRESS_FMT, ee) < 0)
                        return -ENOMEM;
                a = _a;
        }

        r = sd_bus_set_address(b, a);
        if (r >= 0)
                b->is_user = true;
        return r;
}

int bus_set_address_system_remote(sd_bus *b, const char *host) {
        _cleanup_free_ char *e = NULL;
        char *m = NULL, *c = NULL, *a, *rbracket = NULL, *p = NULL;

        assert(b);
        assert(host);

        /* Skip ":"s in ipv6 addresses */
        if (*host == '[') {
                char *t;

                rbracket = strchr(host, ']');
                if (!rbracket)
                        return -EINVAL;
                t = strndupa_safe(host + 1, rbracket - host - 1);
                e = bus_address_escape(t);
                if (!e)
                        return -ENOMEM;
        } else if ((a = strchr(host, '@'))) {
                if (*(a + 1) == '[') {
                        _cleanup_free_ char *t = NULL;

                        rbracket = strchr(a + 1, ']');
                        if (!rbracket)
                                return -EINVAL;
                        t = new0(char, strlen(host));
                        if (!t)
                                return -ENOMEM;
                        strncat(t, host, a - host + 1);
                        strncat(t, a + 2, rbracket - a - 2);
                        e = bus_address_escape(t);
                        if (!e)
                                return -ENOMEM;
                } else if (*(a + 1) == '\0' || strchr(a + 1, '@'))
                        return -EINVAL;
        }

        /* Let's see if a port was given */
        m = strchr(rbracket ? rbracket + 1 : host, ':');
        if (m) {
                char *t;
                bool got_forward_slash = false;

                p = m + 1;

                t = strchr(p, '/');
                if (t) {
                        p = strndupa_safe(p, t - p);
                        got_forward_slash = true;
                }

                if (!in_charset(p, "0123456789") || *p == '\0') {
                        if (!hostname_is_valid(p, 0) || got_forward_slash)
                                return -EINVAL;

                        m = TAKE_PTR(p);
                        goto interpret_port_as_machine_old_syntax;
                }
        }

        /* Let's see if a machine was given */
        m = strchr(rbracket ? rbracket + 1 : host, '/');
        if (m) {
                m++;
interpret_port_as_machine_old_syntax:
                /* Let's make sure this is not a port of some kind,
                 * and is a valid machine name. */
                if (!in_charset(m, "0123456789") && hostname_is_valid(m, 0))
                        c = strjoina(",argv", p ? "7" : "5", "=--machine=", m);
        }

        if (!e) {
                char *t;

                t = strndupa_safe(host, strcspn(host, ":/"));

                e = bus_address_escape(t);
                if (!e)
                        return -ENOMEM;
        }

        a = strjoin("unixexec:path=ssh,argv1=-xT", p ? ",argv2=-p,argv3=" : "", strempty(p),
                                ",argv", p ? "4" : "2", "=--,argv", p ? "5" : "3", "=", e,
                                ",argv", p ? "6" : "4", "=systemd-stdio-bridge", c);
        if (!a)
                return -ENOMEM;

        return free_and_replace(b->address, a);
}
