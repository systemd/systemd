/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "list.h"
#include "shared-forward.h"

typedef enum ConditionType {
        CONDITION_ARCHITECTURE,
        CONDITION_FIRMWARE,
        CONDITION_VIRTUALIZATION,
        CONDITION_HOST,
        CONDITION_KERNEL_COMMAND_LINE,
        CONDITION_VERSION,
        CONDITION_CREDENTIAL,
        CONDITION_SECURITY,
        CONDITION_CAPABILITY,
        CONDITION_AC_POWER,
        CONDITION_MEMORY,
        CONDITION_CPUS,
        CONDITION_ENVIRONMENT,
        CONDITION_CPU_FEATURE,
        CONDITION_OS_RELEASE,
        CONDITION_MEMORY_PRESSURE,
        CONDITION_CPU_PRESSURE,
        CONDITION_IO_PRESSURE,

        CONDITION_NEEDS_UPDATE,
        CONDITION_FIRST_BOOT,

        CONDITION_PATH_EXISTS,
        CONDITION_PATH_EXISTS_GLOB,
        CONDITION_PATH_IS_DIRECTORY,
        CONDITION_PATH_IS_SYMBOLIC_LINK,
        CONDITION_PATH_IS_MOUNT_POINT,
        CONDITION_PATH_IS_READ_WRITE,
        CONDITION_PATH_IS_ENCRYPTED,
        CONDITION_PATH_IS_SOCKET,
        CONDITION_DIRECTORY_NOT_EMPTY,
        CONDITION_FILE_NOT_EMPTY,
        CONDITION_FILE_IS_EXECUTABLE,

        CONDITION_USER,
        CONDITION_GROUP,

        CONDITION_CONTROL_GROUP_CONTROLLER,
        CONDITION_KERNEL_MODULE_LOADED,

        _CONDITION_TYPE_MAX,
        _CONDITION_TYPE_INVALID = -EINVAL,
} ConditionType;

typedef enum ConditionResult {
        CONDITION_UNTESTED,
        CONDITION_SUCCEEDED,
        CONDITION_FAILED,
        CONDITION_ERROR,
        _CONDITION_RESULT_MAX,
        _CONDITION_RESULT_INVALID = -EINVAL,
} ConditionResult;

typedef struct Condition {
        /* Use bitfields for ConditionType and ConditionResult to keep the whole struct in 32 bytes. */
        ConditionType type:8;

        bool trigger;
        bool negate;

        ConditionResult result:8;

        char *parameter;

        LIST_FIELDS(struct Condition, conditions);
} Condition;

Condition* condition_new(ConditionType type, const char *parameter, bool trigger, bool negate);
Condition* condition_free(Condition *c);
Condition* condition_free_list_type(Condition *head, ConditionType type);
static inline Condition* condition_free_list(Condition *first) {
        return condition_free_list_type(first, _CONDITION_TYPE_INVALID);
}

int condition_test(Condition *c, char **env);

typedef int (*condition_test_logger_t)(void *userdata, int level, int error, const char *file, int line, const char *func, const char *format, ...) _printf_(7, 8);
typedef const char* (*condition_to_string_t)(ConditionType t) _const_;
bool condition_test_list(Condition *first, char **env, condition_to_string_t to_string, condition_test_logger_t logger, void *userdata);

void condition_dump(Condition *c, FILE *f, const char *prefix, condition_to_string_t to_string);
void condition_dump_list(Condition *first, FILE *f, const char *prefix, condition_to_string_t to_string);

DECLARE_STRING_TABLE_LOOKUP(condition_type, ConditionType);
void condition_types_list(void);

DECLARE_STRING_TABLE_LOOKUP(assert_type, ConditionType);
void assert_types_list(void);

DECLARE_STRING_TABLE_LOOKUP(condition_result, ConditionResult);

static inline bool condition_takes_path(ConditionType t) {
        return IN_SET(t,
                      CONDITION_PATH_EXISTS,
                      CONDITION_PATH_EXISTS_GLOB,
                      CONDITION_PATH_IS_DIRECTORY,
                      CONDITION_PATH_IS_SYMBOLIC_LINK,
                      CONDITION_PATH_IS_MOUNT_POINT,
                      CONDITION_PATH_IS_READ_WRITE,
                      CONDITION_PATH_IS_ENCRYPTED,
                      CONDITION_PATH_IS_SOCKET,
                      CONDITION_DIRECTORY_NOT_EMPTY,
                      CONDITION_FILE_NOT_EMPTY,
                      CONDITION_FILE_IS_EXECUTABLE,
                      CONDITION_NEEDS_UPDATE);
}
