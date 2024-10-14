/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "unit-dependency-atom.h"

static const UnitDependencyAtom atom_map[_UNIT_DEPENDENCY_MAX] = {
        /* A table that maps high-level dependency types to low-level dependency "atoms". The latter actually
         * describe specific facets of dependency behaviour. The former combine them into one user-facing
         * concept. Atoms are a bit mask, though a bunch of dependency types have only a single bit set.
         *
         * Typically when the user configures a dependency they go via dependency type, but when we act on
         * them we go by atom.
         *
         * NB: when you add a new dependency type here, make sure to also add one to the (best-effort)
         * reverse table in unit_dependency_from_unique_atom() further down. */

        [UNIT_REQUIRES]               = UNIT_ATOM_PULL_IN_START |
                                        UNIT_ATOM_RETROACTIVE_START_REPLACE |
                                        UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                                        UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,

        [UNIT_REQUISITE]              = UNIT_ATOM_PULL_IN_VERIFY |
                                        UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                                        UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,

        [UNIT_WANTS]                  = UNIT_ATOM_PULL_IN_START_IGNORED |
                                        UNIT_ATOM_RETROACTIVE_START_FAIL |
                                        UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                                        UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,

        [UNIT_BINDS_TO]               = UNIT_ATOM_PULL_IN_START |
                                        UNIT_ATOM_RETROACTIVE_START_REPLACE |
                                        UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT |
                                        UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                                        UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,

        [UNIT_UPHOLDS]                = UNIT_ATOM_PULL_IN_START_IGNORED |
                                        UNIT_ATOM_RETROACTIVE_START_REPLACE |
                                        UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE |
                                        UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                                        UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,

        [UNIT_REQUIRED_BY]            = UNIT_ATOM_PROPAGATE_STOP |
                                        UNIT_ATOM_PROPAGATE_START_FAILURE |
                                        UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED |
                                        UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES,

        [UNIT_REQUISITE_OF]           = UNIT_ATOM_PROPAGATE_STOP |
                                        UNIT_ATOM_PROPAGATE_START_FAILURE |
                                        UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE |
                                        UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED |
                                        UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES,

        [UNIT_WANTED_BY]              = UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES |
                                        UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED,

        [UNIT_BOUND_BY]               = UNIT_ATOM_RETROACTIVE_STOP_ON_STOP |
                                        UNIT_ATOM_PROPAGATE_STOP |
                                        UNIT_ATOM_PROPAGATE_START_FAILURE |
                                        UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED |
                                        UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE |
                                        UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES,

        [UNIT_UPHELD_BY]              = UNIT_ATOM_START_STEADILY |
                                        UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES |
                                        UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED,

        [UNIT_CONFLICTS]              = UNIT_ATOM_PULL_IN_STOP |
                                        UNIT_ATOM_RETROACTIVE_STOP_ON_START,

        [UNIT_CONFLICTED_BY]          = UNIT_ATOM_PULL_IN_STOP_IGNORED |
                                        UNIT_ATOM_RETROACTIVE_STOP_ON_START |
                                        UNIT_ATOM_PROPAGATE_STOP_FAILURE,

        [UNIT_PROPAGATES_STOP_TO]     = UNIT_ATOM_RETROACTIVE_STOP_ON_STOP |
                                        UNIT_ATOM_PROPAGATE_STOP_GRACEFUL,

        /* These are simple dependency types: they consist of a single atom only */
        [UNIT_ON_FAILURE]             = UNIT_ATOM_ON_FAILURE,
        [UNIT_ON_SUCCESS]             = UNIT_ATOM_ON_SUCCESS,
        [UNIT_ON_FAILURE_OF]          = UNIT_ATOM_ON_FAILURE_OF,
        [UNIT_ON_SUCCESS_OF]          = UNIT_ATOM_ON_SUCCESS_OF,
        [UNIT_BEFORE]                 = UNIT_ATOM_BEFORE,
        [UNIT_AFTER]                  = UNIT_ATOM_AFTER,
        [UNIT_PART_OF]                = UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE,
        [UNIT_CONSISTS_OF]            = UNIT_ATOM_PROPAGATE_STOP,
        [UNIT_TRIGGERS]               = UNIT_ATOM_TRIGGERS,
        [UNIT_TRIGGERED_BY]           = UNIT_ATOM_TRIGGERED_BY,
        [UNIT_PROPAGATES_RELOAD_TO]   = UNIT_ATOM_PROPAGATES_RELOAD_TO,
        [UNIT_JOINS_NAMESPACE_OF]     = UNIT_ATOM_JOINS_NAMESPACE_OF,
        [UNIT_REFERENCES]             = UNIT_ATOM_REFERENCES,
        [UNIT_REFERENCED_BY]          = UNIT_ATOM_REFERENCED_BY,
        [UNIT_IN_SLICE]               = UNIT_ATOM_IN_SLICE,
        [UNIT_SLICE_OF]               = UNIT_ATOM_SLICE_OF,

        /* These are dependency types without effect on our state engine. We maintain them only to make
         * things discoverable/debuggable as they are the inverse dependencies to some of the above. As they
         * have no effect of their own, they all map to no atoms at all, i.e. the value 0. */
        [UNIT_RELOAD_PROPAGATED_FROM] = 0,
        [UNIT_STOP_PROPAGATED_FROM]   = 0,
};

UnitDependencyAtom unit_dependency_to_atom(UnitDependency d) {
        if (d < 0)
                return _UNIT_DEPENDENCY_ATOM_INVALID;

        assert(d < _UNIT_DEPENDENCY_MAX);

        return atom_map[d];
}

UnitDependency unit_dependency_from_unique_atom(UnitDependencyAtom atom) {

        /* This is a "best-effort" function that maps the specified 'atom' mask to a dependency type that is
         * is equal to or has a superset of bits set if that's uniquely possible. The idea is that this
         * function is used when iterating through deps that have a specific atom: if there's exactly one
         * dependency type of the specific atom we don't need iterate through all deps a unit has, but can
         * pinpoint things directly.
         *
         * This function will return _UNIT_DEPENDENCY_INVALID in case the specified value is not known or not
         * uniquely defined, i.e. there are multiple dependencies with the atom or the combination set. */

        switch ((int64_t) atom) {

                /* Note that we can't list UNIT_REQUIRES here since it's a true subset of UNIT_BINDS_TO, and
                 * hence its atom bits not uniquely mappable. */

        case UNIT_ATOM_PULL_IN_VERIFY |
                UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE:
        case UNIT_ATOM_PULL_IN_VERIFY: /* a single dep type uses this atom */
                return UNIT_REQUISITE;

        case UNIT_ATOM_PULL_IN_START_IGNORED |
                UNIT_ATOM_RETROACTIVE_START_FAIL |
                UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE:
        case UNIT_ATOM_RETROACTIVE_START_FAIL:
                return UNIT_WANTS;

        case UNIT_ATOM_PULL_IN_START |
                UNIT_ATOM_RETROACTIVE_START_REPLACE |
                UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT |
                UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE:
        case UNIT_ATOM_CANNOT_BE_ACTIVE_WITHOUT:
                return UNIT_BINDS_TO;

        case UNIT_ATOM_PULL_IN_START_IGNORED |
                UNIT_ATOM_RETROACTIVE_START_REPLACE |
                UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE |
                UNIT_ATOM_ADD_STOP_WHEN_UNNEEDED_QUEUE |
                UNIT_ATOM_ADD_DEFAULT_TARGET_DEPENDENCY_QUEUE:
        case UNIT_ATOM_ADD_START_WHEN_UPHELD_QUEUE:
                return UNIT_UPHOLDS;

        case UNIT_ATOM_PROPAGATE_STOP |
                UNIT_ATOM_PROPAGATE_START_FAILURE |
                UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE |
                UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED |
                UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES:
        case UNIT_ATOM_PROPAGATE_INACTIVE_START_AS_FAILURE:
                return UNIT_REQUISITE_OF;

        case UNIT_ATOM_RETROACTIVE_STOP_ON_STOP |
                UNIT_ATOM_PROPAGATE_STOP |
                UNIT_ATOM_PROPAGATE_START_FAILURE |
                UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED |
                UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE |
                UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES:
        case UNIT_ATOM_ADD_CANNOT_BE_ACTIVE_WITHOUT_QUEUE:
                return UNIT_BOUND_BY;

        case UNIT_ATOM_START_STEADILY |
                UNIT_ATOM_DEFAULT_TARGET_DEPENDENCIES |
                UNIT_ATOM_PINS_STOP_WHEN_UNNEEDED:
        case UNIT_ATOM_START_STEADILY:
                return UNIT_UPHELD_BY;

        case UNIT_ATOM_PULL_IN_STOP |
                UNIT_ATOM_RETROACTIVE_STOP_ON_START:
        case UNIT_ATOM_PULL_IN_STOP:
                return UNIT_CONFLICTS;

        case UNIT_ATOM_PULL_IN_STOP_IGNORED |
                UNIT_ATOM_RETROACTIVE_STOP_ON_START |
                UNIT_ATOM_PROPAGATE_STOP_FAILURE:
        case UNIT_ATOM_PULL_IN_STOP_IGNORED:
        case UNIT_ATOM_PROPAGATE_STOP_FAILURE:
                return UNIT_CONFLICTED_BY;

        case UNIT_ATOM_RETROACTIVE_STOP_ON_STOP |
                UNIT_ATOM_PROPAGATE_STOP_GRACEFUL:
        case UNIT_ATOM_PROPAGATE_STOP_GRACEFUL:
                return UNIT_PROPAGATES_STOP_TO;

        /* And now, the simple ones */

        case UNIT_ATOM_ON_FAILURE:
                return UNIT_ON_FAILURE;

        case UNIT_ATOM_ON_SUCCESS:
                return UNIT_ON_SUCCESS;

        case UNIT_ATOM_ON_SUCCESS_OF:
                return UNIT_ON_SUCCESS_OF;

        case UNIT_ATOM_ON_FAILURE_OF:
                return UNIT_ON_FAILURE_OF;

        case UNIT_ATOM_BEFORE:
                return UNIT_BEFORE;

        case UNIT_ATOM_AFTER:
                return UNIT_AFTER;

        case UNIT_ATOM_TRIGGERS:
                return UNIT_TRIGGERS;

        case UNIT_ATOM_TRIGGERED_BY:
                return UNIT_TRIGGERED_BY;

        case UNIT_ATOM_PROPAGATES_RELOAD_TO:
                return UNIT_PROPAGATES_RELOAD_TO;

        case UNIT_ATOM_JOINS_NAMESPACE_OF:
                return UNIT_JOINS_NAMESPACE_OF;

        case UNIT_ATOM_REFERENCES:
                return UNIT_REFERENCES;

        case UNIT_ATOM_REFERENCED_BY:
                return UNIT_REFERENCED_BY;

        case UNIT_ATOM_IN_SLICE:
                return UNIT_IN_SLICE;

        case UNIT_ATOM_SLICE_OF:
                return UNIT_SLICE_OF;

        default:
                return _UNIT_DEPENDENCY_INVALID;
        }
}
