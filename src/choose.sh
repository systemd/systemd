
result="$4"

case "$1" in
  *c*) ./compile $2.c >/dev/null 2>&1 || result="$3" ;;
esac

case "$1" in
  *l*) ./load $2 >/dev/null 2>&1 || result="$3" ;;
esac

case "$1" in
  *r*) ./$2 >/dev/null 2>&1 || result="$3" ;;
esac

rm -f $2.o $2

exec cat "$result"
