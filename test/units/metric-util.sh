#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Utility functions for metric tests

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
