ld="`head -n1 conf-ld`"
systype="`cat systype`"

cat warn-auto.sh
echo 'main="$1"; shift'
echo exec "$ld" '-o "$main" "$main".o ${1+"$@"}'
