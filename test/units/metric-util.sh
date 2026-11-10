#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Utility functions for metric tests

# shellcheck source=test/units/util.sh
. "$(dirname "${BASH_SOURCE[0]}")"/util.sh

metric_select_full() {
    local metrics="${1?}"
    local condition=true i=0
    local -a args=()
    shift

    while (( $# > 0 )); do
        case "$1" in
            --name)
                args+=(--arg "name$i" "${2:?Missing metric name}")
                condition+=" and .name == \$name$i"
                shift 2
                ;;
            --name-prefix)
                args+=(--arg "prefix$i" "${2?Missing metric name prefix}")
                condition+=" and (.name | startswith(\$prefix$i))"
                shift 2
                ;;
            --object)
                args+=(--arg "object$i" "${2?Missing object value}")
                condition+=" and .object == \$object$i"
                shift 2
                ;;
            --field)
                args+=(--arg "key$i" "${2?Missing field name}"
                       --arg "value$i" "${3?Missing field value}")
                condition+=" and .fields[\$key$i] == \$value$i"
                shift 3
                ;;
            *)
                printf 'Unknown metric filter: %s\n' "$1" >&2
                return 2
                ;;
        esac
        i=$((i + 1))
    done

    # Emit ordinary JSON so an empty selection is valid input to subsequent jq calls.
    jq --seq -r "${args[@]}" "select($condition) | tojson" <<<"$metrics"
}

metric_select() {
    local metrics="${1?}" name="${2:?}"
    shift 2

    metric_select_full "$metrics" --name "$name" "$@"
}

metric_value() {
    metric_select "$@" | jq -r '.value | tostring'
}

metric_count() {
    metric_select_full "$@" | jq -s 'length'
}

assert_metric_count_eq() {
    local metrics="${1?}" expected="${2:?}"
    local count
    shift 2

    count="$(metric_count "$metrics" "$@")" || return
    assert_eq "$count" "$expected"
}

assert_metric_absent_full() {
    local matches

    matches="$(metric_select_full "$@")" || return
    assert_empty "$matches"
}

assert_metric_absent() {
    local metrics="${1?}" name="${2:?}"
    shift 2

    assert_metric_absent_full "$metrics" --name "$name" "$@"
}

assert_metric_value_eq() {
    local metrics="${1?}" name="${2:?}" expected="${3?}"
    local value
    shift 3

    value="$(metric_value "$metrics" "$name" "$@")" || return
    assert_eq "$value" "$expected"
}

assert_metric_value_ge() {
    local metrics="${1?}" name="${2:?}" expected="${3:?}"
    local value
    shift 3

    value="$(metric_value "$metrics" "$name" "$@")" || return
    assert_ge "$value" "$expected"
}

assert_metric_value_le() {
    local metrics="${1?}" name="${2:?}" expected="${3:?}"
    local value
    shift 3

    value="$(metric_value "$metrics" "$name" "$@")" || return
    assert_le "$value" "$expected"
}

assert_metric_value_gt() {
    local metrics="${1?}" name="${2:?}" expected="${3:?}"
    local value
    shift 3

    value="$(metric_value "$metrics" "$name" "$@")" || return
    assert_gt "$value" "$expected"
}

assert_metric_value_lt() {
    local metrics="${1?}" name="${2:?}" expected="${3:?}"
    local value
    shift 3

    value="$(metric_value "$metrics" "$name" "$@")" || return
    assert_lt "$value" "$expected"
}

assert_metric_value_not_empty() {
    local value

    value="$(metric_value "$@")" || return
    assert_not_empty "$value"
}

assert_metric_value_is_number() {
    local type

    type="$(metric_select "$@" | jq -r '.value | type' | sort -u)" || return
    assert_eq "$type" number
}

assert_metric_values_in_range() {
    local metrics="${1?}" name="${2:?}" min="${3:?}" max="${4:?}"
    local result
    shift 4

    result="$(metric_select "$metrics" "$name" "$@" | jq -rs --argjson min "$min" --argjson max "$max" '
        length > 0 and all(.[]; (.value | type) == "number" and .value >= $min and .value <= $max)')" || return
    assert_eq "$result" true
}

assert_metric_value_float_eq() {
    local metrics="${1?}" name="${2:?}" expected="${3:?}" tolerance="${4:?}"
    local result
    shift 4

    result="$(metric_select "$metrics" "$name" "$@" | jq -r --argjson expected "$expected" --argjson tolerance "$tolerance" '
        (.value | type) == "number" and ((.value - $expected | fabs) < $tolerance)')" || return
    assert_eq "$result" true
}

assert_metric_type_eq() {
    local metrics="${1?}" name="${2:?}" expected="${3:?}"
    local type
    shift 3

    type="$(metric_select "$metrics" "$name" "$@" | jq -r '.type')" || return
    assert_eq "$type" "$expected"
}

assert_metric_object_eq() {
    local metrics="${1?}" name="${2:?}" expected="${3:?}"
    local object
    shift 3

    object="$(metric_select "$metrics" "$name" "$@" | jq -r '.object')" || return
    assert_eq "$object" "$expected"
}

assert_metric_field_eq() {
    local metrics="${1?}" field="${2:?}" expected="${3?}"
    local result
    shift 3

    result="$(metric_select_full "$metrics" "$@" |
        jq -rs --arg field "$field" --arg expected "$expected" '
            length > 0 and all(.[];
                (.fields | has($field)) and
                (.fields[$field] | tostring) == $expected)
        ')" || return
    assert_eq "$result" true
}

assert_metric_field_absent() {
    local metrics="${1?}" field="${2:?}"
    local result
    shift 2

    result="$(metric_select_full "$metrics" "$@" | jq -rs --arg field "$field" '
        length > 0 and all(.[]; .fields | has($field) | not)')" || return
    assert_eq "$result" true
}
