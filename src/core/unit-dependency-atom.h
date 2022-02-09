/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>

#include "unit-def.h"

/* Flags that identify the various "atomic" behaviours a specific dependency type implies. Each dependency is
 * a combination of one or more of these flags that define what they actually entail. */
typedef enum UnitDependencyAtom {

        /* This unit pulls in the other unit as JOB_START job into the transaction, and if that doesn't work
         * the transaction fails. */
        UNIT_ATOM_PULL_IN_START                       = UINT64_C(1) << 0,
        /* Similar, but if it doesn't work, ignore. */
        UNIT_ATOM_PULL_IN_START_IGNORED               = UINT64_C(1) << 1,
        /* Pull in a JOB_VERIFY job into the transaction, i.e. pull in JOB_VERIFY rather than
         * JOB_START. i.e. check the unit is started but don't pull it in. */
        UNIT_ATOM_PULL_IN_VERIFY                      = UINT64_C(1) << 2,

        /* Pull in a JOB_STOP job for the other job into transactions, and fail if that doesn't work. */
        UNIT_ATOM_PULL_IN_STOP                        = UINT64_C(1) << 3,
        /* Same, but don't fail, ignore it. */
        UNIT_ATOM_PULL_IN_STOP_IGNORED                = UINT64_C(1) << 4,

        /* If our enters inactive state, add the other unit to the StopWhenUneeded= queue */
        UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE        = UINT64_C(1) << 5,
        /* Pin the other unit i.e. ensure StopWhenUneeded= won't trigger for the other unit as long as we are
         * not in inactive state */
        UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED             = UINT64_C(1) << 6,

        /* Stop our unit if the other unit happens to inactive */
        UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT            = UINT64_C(1) << 7,
        /* If our unit enters inactive state, add the other unit to the BoundBy= queue */
        UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE  = UINT64_C(1) << 8,

        /* Start this unit whenever we find it inactive and the other unit active */
        UNIT_ATOM_START_STEADILY                      = UINT64_C(1) << 9,
        /* Whenever our unit becomes active, add other unit to start_when_upheld_queue */
        UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE         = UINT64_C(1) << 10,

        /* If our unit unexpectedly becomes active, retroactively start the other unit too, in "replace" job
         * mode */
        UNIT_ATOM_RETROACTIVE_START_REPLACE           = UINT64_C(1) << 11,
        /* Similar, but in "fail" job mode */
        UNIT_ATOM_RETROACTIVE_START_FAIL              = UINT64_C(1) << 12,
        /* If our unit unexpectedly becomes active, retroactively stop the other unit too */
        UNIT_ATOM_RETROACTIVE_STOP_ON_START           = UINT64_C(1) << 13,
        /* If our unit unexpectedly becomes inactive, retroactively stop the other unit too */
        UNIT_ATOM_RETROACTIVE_STOP_ON_STOP            = UINT64_C(1) << 14,

        /* If a start job for this unit fails, propagate the failure to start job of other unit too */
        UNIT_ATOM_PROPAGATE_START_FAILURE             = UINT64_C(1) << 15,
        /* If a stop job for this unit fails, propagate the failure to any stop job of the other unit too */
        UNIT_ATOM_PROPAGATE_STOP_FAILURE              = UINT64_C(1) << 16,
        /* If our start job succeeded but the unit is inactive then (think: oneshot units), propagate this as
         * failure to the other unit. */
        UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE = UINT64_C(1) << 17,
        /* When putting together a transaction, propagate JOB_STOP from our unit to the other. */
        UNIT_ATOM_PROPAGATE_STOP                      = UINT64_C(1) << 18,
        /* When putting together a transaction, propagate JOB_RESTART from our unit to the other. */
        UNIT_ATOM_PROPAGATE_RESTART                   = UINT64_C(1) << 19,

        /* Add the other unit to the default target dependency queue */
        UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE = UINT64_C(1) << 20,
        /* Recheck default target deps on other units (which are target units) */
        UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES         = UINT64_C(1) << 21,

        /* The remaining atoms map 1:1 to the equally named high-level deps */
        UNIT_ATOM_ON_FAILURE                          = UINT64_C(1) << 22,
        UNIT_ATOM_ON_SUCCESS                          = UINT64_C(1) << 23,
        UNIT_ATOM_ON_FAILURE_OF                       = UINT64_C(1) << 24,
        UNIT_ATOM_ON_SUCCESS_OF                       = UINT64_C(1) << 25,
        UNIT_ATOM_BEFORE                              = UINT64_C(1) << 26,
        UNIT_ATOM_AFTER                               = UINT64_C(1) << 27,
        UNIT_ATOM_TRIGGERS                            = UINT64_C(1) << 28,
        UNIT_ATOM_TRIGGERED_BY                        = UINT64_C(1) << 29,
        UNIT_ATOM_PROPAGATES_RELOAD_TO                = UINT64_C(1) << 30,
        UNIT_ATOM_JOINS_NAMESPACE_OF                  = UINT64_C(1) << 31,
        UNIT_ATOM_REFERENCES                          = UINT64_C(1) << 32,
        UNIT_ATOM_REFERENCED_BY                       = UINT64_C(1) << 33,
        UNIT_ATOM_IN_SLICE                            = UINT64_C(1) << 34,
        UNIT_ATOM_SLICE_OF                            = UINT64_C(1) << 35,
        _UNIT_DEPENDENCY_ATOM_MAX                     = (UINT64_C(1) << 36) - 1,
        _UNIT_DEPENDENCY_ATOM_INVALID                 = -EINVAL,
} UnitDependencyAtom;

UnitDependencyAtom unit_dependency_to_atom(UnitDependency d);
UnitDependency unit_dependency_from_unique_atom(UnitDependencyAtom atom);
