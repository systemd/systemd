/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdlib.h>

#include "analyze-condition.h"
#include "condition.h"
#include "conf-parser.h"
#include "load-fragment.h"
#include "service.h"

typedef struct condition_definition {
        const char *name;
        ConfigParserCallback parser;
        ConditionType type;
} condition_definition;

static const condition_definition condition_definitions[] = {
        { "ConditionPathExists",             config_parse_unit_condition_path,   CONDITION_PATH_EXISTS              },
        { "ConditionPathExistsGlob",         config_parse_unit_condition_path,   CONDITION_PATH_EXISTS_GLOB         },
        { "ConditionPathIsDirectory",        config_parse_unit_condition_path,   CONDITION_PATH_IS_DIRECTORY        },
        { "ConditionPathIsSymbolicLink",     config_parse_unit_condition_path,   CONDITION_PATH_IS_SYMBOLIC_LINK    },
        { "ConditionPathIsMountPoint",       config_parse_unit_condition_path,   CONDITION_PATH_IS_MOUNT_POINT      },
        { "ConditionPathIsReadWrite",        config_parse_unit_condition_path,   CONDITION_PATH_IS_READ_WRITE       },
        { "ConditionDirectoryNotEmpty",      config_parse_unit_condition_path,   CONDITION_DIRECTORY_NOT_EMPTY      },
        { "ConditionFileNotEmpty",           config_parse_unit_condition_path,   CONDITION_FILE_NOT_EMPTY           },
        { "ConditionFileIsExecutable",       config_parse_unit_condition_path,   CONDITION_FILE_IS_EXECUTABLE       },
        { "ConditionNeedsUpdate",            config_parse_unit_condition_path,   CONDITION_NEEDS_UPDATE             },
        { "ConditionFirstBoot",              config_parse_unit_condition_string, CONDITION_FIRST_BOOT               },
        { "ConditionKernelCommandLine",      config_parse_unit_condition_string, CONDITION_KERNEL_COMMAND_LINE      },
        { "ConditionKernelVersion",          config_parse_unit_condition_string, CONDITION_KERNEL_VERSION           },
        { "ConditionArchitecture",           config_parse_unit_condition_string, CONDITION_ARCHITECTURE             },
        { "ConditionVirtualization",         config_parse_unit_condition_string, CONDITION_VIRTUALIZATION           },
        { "ConditionSecurity",               config_parse_unit_condition_string, CONDITION_SECURITY                 },
        { "ConditionCapability",             config_parse_unit_condition_string, CONDITION_CAPABILITY               },
        { "ConditionHost",                   config_parse_unit_condition_string, CONDITION_HOST                     },
        { "ConditionACPower",                config_parse_unit_condition_string, CONDITION_AC_POWER                 },
        { "ConditionUser",                   config_parse_unit_condition_string, CONDITION_USER                     },
        { "ConditionGroup",                  config_parse_unit_condition_string, CONDITION_GROUP                    },
        { "ConditionControlGroupController", config_parse_unit_condition_string, CONDITION_CONTROL_GROUP_CONTROLLER },

        { "AssertPathExists",                config_parse_unit_condition_path,   CONDITION_PATH_EXISTS              },
        { "AssertPathExistsGlob",            config_parse_unit_condition_path,   CONDITION_PATH_EXISTS_GLOB         },
        { "AssertPathIsDirectory",           config_parse_unit_condition_path,   CONDITION_PATH_IS_DIRECTORY        },
        { "AssertPathIsSymbolicLink",        config_parse_unit_condition_path,   CONDITION_PATH_IS_SYMBOLIC_LINK    },
        { "AssertPathIsMountPoint",          config_parse_unit_condition_path,   CONDITION_PATH_IS_MOUNT_POINT      },
        { "AssertPathIsReadWrite",           config_parse_unit_condition_path,   CONDITION_PATH_IS_READ_WRITE       },
        { "AssertDirectoryNotEmpty",         config_parse_unit_condition_path,   CONDITION_DIRECTORY_NOT_EMPTY      },
        { "AssertFileNotEmpty",              config_parse_unit_condition_path,   CONDITION_FILE_NOT_EMPTY           },
        { "AssertFileIsExecutable",          config_parse_unit_condition_path,   CONDITION_FILE_IS_EXECUTABLE       },
        { "AssertNeedsUpdate",               config_parse_unit_condition_path,   CONDITION_NEEDS_UPDATE             },
        { "AssertFirstBoot",                 config_parse_unit_condition_string, CONDITION_FIRST_BOOT               },
        { "AssertKernelCommandLine",         config_parse_unit_condition_string, CONDITION_KERNEL_COMMAND_LINE      },
        { "AssertKernelVersion",             config_parse_unit_condition_string, CONDITION_KERNEL_VERSION           },
        { "AssertArchitecture",              config_parse_unit_condition_string, CONDITION_ARCHITECTURE             },
        { "AssertVirtualization",            config_parse_unit_condition_string, CONDITION_VIRTUALIZATION           },
        { "AssertSecurity",                  config_parse_unit_condition_string, CONDITION_SECURITY                 },
        { "AssertCapability",                config_parse_unit_condition_string, CONDITION_CAPABILITY               },
        { "AssertHost",                      config_parse_unit_condition_string, CONDITION_HOST                     },
        { "AssertACPower",                   config_parse_unit_condition_string, CONDITION_AC_POWER                 },
        { "AssertUser",                      config_parse_unit_condition_string, CONDITION_USER                     },
        { "AssertGroup",                     config_parse_unit_condition_string, CONDITION_GROUP                    },
        { "AssertControlGroupController",    config_parse_unit_condition_string, CONDITION_CONTROL_GROUP_CONTROLLER },

        /* deprecated, but we should still parse them */
        { "ConditionNull",                   config_parse_unit_condition_null,   0                                  },
        { "AssertNull",                      config_parse_unit_condition_null,   0                                  },
};

static int parse_condition(Unit *u, const char *line) {
        const char *p;
        Condition **target;

        if ((p = startswith(line, "Condition")))
                target = &u->conditions;
        else if ((p = startswith(line, "Assert")))
                target = &u->asserts;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot parse \"%s\".", line);

        for (size_t i = 0; i < ELEMENTSOF(condition_definitions); i++) {
                const condition_definition *c = &condition_definitions[i];

                p = startswith(line, c->name);
                if (!p)
                        continue;
                p += strspn(p, WHITESPACE);
                if (*p != '=')
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected \"=\" in \"%s\".", line);

                p += 1 + strspn(p + 1, WHITESPACE);

                return c->parser(NULL, "(stdin)", 0, NULL, 0, c->name, c->type, p, target, u);
        }

        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot parse \"%s\".", line);
}

_printf_(7, 8)
static int log_helper(void *userdata, int level, int error, const char *file, int line, const char *func, const char *format, ...) {
        Unit *u = userdata;
        va_list ap;
        int r;

        assert(u);

        /* "upgrade" debug messages */
        level = MIN(LOG_INFO, level);

        va_start(ap, format);
        r = log_object_internalv(level, error, file, line, func,
                                 NULL,
                                 u->id,
                                 NULL,
                                 NULL,
                                 format, ap);
        va_end(ap);

        return r;
}

int verify_conditions(char **lines, UnitFileScope scope) {
        _cleanup_(manager_freep) Manager *m = NULL;
        Unit *u;
        char **line;
        int r, q = 1;

        r = manager_new(scope, MANAGER_TEST_RUN_MINIMAL, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize manager: %m");

        log_debug("Starting manager...");
        r = manager_startup(m, NULL, NULL);
        if (r < 0)
                return r;

        r = unit_new_for_name(m, sizeof(Service), "test.service", &u);
        if (r < 0)
                return log_error_errno(r, "Failed to create test.service: %m");

        STRV_FOREACH(line, lines) {
                r = parse_condition(u, *line);
                if (r < 0)
                        return r;
        }

        r = condition_test_list(u->asserts, assert_type_to_string, log_helper, u);
        if (u->asserts)
                log_notice("Asserts %s.", r > 0 ? "succeeded" : "failed");

        q = condition_test_list(u->conditions, condition_type_to_string, log_helper, u);
        if (u->conditions)
                log_notice("Conditions %s.", q > 0 ? "succeeded" : "failed");

        return r > 0 && q > 0 ? 0 : -EIO;
}
