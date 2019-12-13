# This was borrowed from https://github.com/travis-ci/travis-build/tree/master/lib/travis/build/bash
# to get around https://github.com/travis-ci/travis-ci/issues/9979. It should probably be removed
# as soon as Travis CI has started to provide an easy way to export the functions to bash scripts.

travis_jigger() {
    local cmd_pid="${1}"
    shift
    local timeout="${1}"
    shift
    local count=0

    echo -e "\\n"

    while [[ "${count}" -lt "${timeout}" ]]; do
        count="$((count + 1))"
        echo -ne "Still running (${count} of ${timeout}): ${*}\\r"
        sleep 60
    done

    echo -e "\\n${ANSI_RED}Timeout (${timeout} minutes) reached. Terminating \"${*}\"${ANSI_RESET}\\n"
    kill -9 "${cmd_pid}"
}

travis_wait() {
    local timeout="${1}"

    if [[ "${timeout}" =~ ^[0-9]+$ ]]; then
        shift
    else
        timeout=20
    fi

    local cmd=("${@}")
    local log_file="travis_wait_${$}.log"

    "${cmd[@]}" &>"${log_file}" &
    local cmd_pid="${!}"

    travis_jigger "${!}" "${timeout}" "${cmd[@]}" &
    local jigger_pid="${!}"
    local result

    {
        set +e
        wait "${cmd_pid}" 2>/dev/null
        result="${?}"
        ps -p"${jigger_pid}" &>/dev/null && kill "${jigger_pid}"
        set -e
    }

    if [[ "${result}" -eq 0 ]]; then
        echo -e "\\n${ANSI_GREEN}The command ${cmd[*]} exited with ${result}.${ANSI_RESET}"
    else
        echo -e "\\n${ANSI_RED}The command ${cmd[*]} exited with ${result}.${ANSI_RESET}"
    fi

    echo -e "\\n${ANSI_GREEN}Log:${ANSI_RESET}\\n"
    cat "${log_file}"

    return "${result}"
}
