#!/bin/sh

top_srcdir=${top_srcdir:-../..}
. ${top_srcdir}/test/setup_env.sh

libeinfo_srcdir="${srcdir}/../libeinfo"
libeinfo_builddir="${builddir}/../libeinfo"
librc_srcdir="${srcdir}/../librc"
librc_builddir="${builddir}/../librc"
rc_srcdir="${srcdir}/../rc"
rc_builddir="${builddir}/../rc"

checkit() {
	local base=$1; shift
	echo "$@" | tr ' ' '\n' > ${base}.out
	diff -u ${base}.list ${base}.out
	eend $?
	: $(( ret += $? ))
}

ret=0

ebegin "Checking exported symbols in libeinfo.so (data)"
checkit einfo.data $(
readelf -Ws ${libeinfo_builddir}/libeinfo.so \
	| awk '$4 == "OBJECT" && $5 == "GLOBAL" && $7 != "UND" {print $NF}' \
	| LC_ALL=C sort -u
)

ebegin "Checking exported symbols in libeinfo.so (functions)"
checkit einfo.funcs $(
readelf -Ws ${libeinfo_builddir}/libeinfo.so \
	| awk '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" {print $NF}' \
	| LC_ALL=C sort -u \
	| egrep -v \
		-e '^_(init|fini)$'
)

ebegin "Checking exported symbols in librc.so (data)"
checkit rc.data $(
readelf -Ws ${librc_builddir}/librc.so \
	| awk '$4 == "OBJECT" && $5 == "GLOBAL" && $7 != "UND" {print $NF}' \
	| LC_ALL=C sort -u
)

ebegin "Checking exported symbols in librc.so (functions)"
checkit rc.funcs $(
readelf -Ws ${librc_builddir}/librc.so \
	| awk '$4 == "FUNC" && $5 == "GLOBAL" && $7 != "UND" {print $NF}' \
	| LC_ALL=C sort -u \
	| egrep -v \
		-e '^_(init|fini)$'
)

ebegin "Checking hidden functions in librc.so"
sed -n '/^librc_hidden_proto/s:.*(\(.*\))$:\1:p' ${librc_srcdir}/librc.h \
	| LC_ALL=C sort -u \
	> librc.funcs.hidden.list
readelf -Wr $(grep -l '#include[[:space:]]"librc\.h"' ${librc_srcdir}/*.c | sed 's:\.c$:.o:') \
	| egrep -v -e 'R_PARISC_(DP|SEG)REL' \
	| awk '$5 ~ /^rc_/ {print $5}' \
	| LC_ALL=C sort -u \
	| egrep -v '^rc_environ_fd$' \
	> librc.funcs.hidden.out
syms=$(diff -u librc.funcs.hidden.list librc.funcs.hidden.out | sed -n '/^+[^+]/s:^+::p')
[ -z "${syms}" ]
eend $? "Missing hidden defs:"$'\n'"${syms}"
: $(( ret += $? ))

ebegin "Checking trailing whitespace in code"
# XXX: Should we check man pages too ?
out=$(cd ${top_srcdir}; find */ \
	'(' -name '*.[ch]' -o -name '*.in' -o -name '*.sh' ')' \
	-exec grep -n -E '[[:space:]]+$' {} +)
[ -z "${out}" ]
eend $? "Trailing whitespace needs to be deleted:"$'\n'"${out}"

ebegin "Checking trailing newlines in code"
out=$(cd ${top_srcdir};
	for f in `find */ -name '*.[ch]'` ; do
		sed -n -e :a -e '/^\n*$/{$q1;N;ba' -e '}' $f || echo $f
	done)
[ -z "${out}" ]
eend $? "Trailing newlines need to be deleted:"$'\n'"${out}"

ebegin "Checking for obsolete functions"
out=$(cd ${top_srcdir}; find src -name '*.[ch]' \
	! -name queue.h \
	-exec grep -n -E '\<(malloc|memory|sys/(errno|fcntl|signal|stropts|termios|unistd))\.h\>' {} +)
[ -z "${out}" ]
eend $? "Avoid these obsolete functions:"$'\n'"${out}"

ebegin "Checking for x* func usage"
out=$(cd ${top_srcdir}; find src -name '*.[ch]' \
	! -name queue.h \
	-exec grep -n -E '\<(malloc|strdup)[[:space:]]*\(' {} + \
	| grep -v \
		-e src/includes/helpers.h \
		-e src/libeinfo/libeinfo.c)
[ -z "${out}" ]
eend $? "These need to be using the x* variant:"$'\n'"${out}"

ebegin "Checking spacing style"
out=$(cd ${top_srcdir}; find src -name '*.[ch]' \
	! -name queue.h \
	-exec grep -n -E \
		-e '\<(for|if|switch|while)\(' \
		-e '\<(for|if|switch|while) \( ' \
		-e ' ;' \
		-e '[[:space:]]$' \
		-e '\){' \
		-e '(^|[^:])//' \
	{} +)
[ -z "${out}" ]
eend $? "These lines violate style rules:"$'\n'"${out}"

einfo "Running unit tests"
eindent
for u in units/*; do
	[ -x "${u}" -a -f "${u}" ] || continue
	ebegin "$(basename "${u}")"
	./"${u}"
	eend $?
	: $(( ret += $? ))
done

exit ${ret}
