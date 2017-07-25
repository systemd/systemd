# oper-:arch-:syst-:chip-:kern-
# oper = operating system type; e.g., sunos-4.1.4
# arch = machine language; e.g., sparc
# syst = which binaries can run; e.g., sun4
# chip = chip model; e.g., micro-2-80
# kern = kernel version; e.g., sun4m
# dependence: arch --- chip
#                 \        \
#          oper --- syst --- kern
# so, for example, syst is interpreted in light of oper, but chip is not.
# anyway, no slashes, no extra colons, no uppercase letters.
# the point of the extra -'s is to ease parsing: can add hierarchies later.
# e.g., *:i386-*:*:pentium-*:* would handle pentium-100 as well as pentium,
# and i386-486 (486s do have more instructions, you know) as well as i386.
# the idea here is to include ALL useful available information.

exec 2>/dev/null

sys="`uname -s | tr '/:[A-Z]' '..[a-z]'`"
if [ x"$sys" != x ]
then
  unamer="`uname -r | tr /: ..`"
  unamem="`uname -m | tr /: ..`"
  unamev="`uname -v | tr /: ..`"

  case "$sys" in
  bsd.os|freebsd|netbsd|openbsd)
    # in bsd 4.4, uname -v does not have useful info.
    # in bsd 4.4, uname -m is arch, not chip.
    oper="$sys-$unamer"
    arch="$unamem"
    syst=""
    chip="`sysctl -n hw.model`" # hopefully
    kern=""
    ;;
  linux)
    # as in bsd 4.4, uname -v does not have useful info.
    oper="$sys-$unamer"
    syst=""
    chip="$unamem"
    kern=""
    case "$chip" in
    i386|i486|i586|i686)
      arch="i386"
      ;;
    alpha)
      arch="alpha"
      ;;
    esac
    ;;
  aix)
    # naturally IBM has to get uname -r and uname -v backwards. dorks.
    oper="$sys-$unamev-$unamer"
    arch="`arch | tr /: ..`"
    syst=""
    chip="$unamem"
    kern=""
    ;;
  sunos)
    oper="$sys-$unamer-$unamev"
    arch="`(uname -p || mach) | tr /: ..`"
    syst="`arch | tr /: ..`"
    chip="$unamem" # this is wrong; is there any way to get the real info?
    kern="`arch -k | tr /: ..`"
    ;;
  unix_sv)
    oper="$sys-$unamer-$unamev"
    arch="`uname -m`"
    syst=""
    chip="$unamem"
    kern=""
    ;;
  *)
    oper="$sys-$unamer-$unamev"
    arch="`arch | tr /: ..`"
    syst=""
    chip="$unamem"
    kern=""
    ;;
  esac
else
  gcc -c trycpp.c
  gcc -o trycpp trycpp.o
  case `./trycpp` in
  nextstep)
    oper="nextstep-`hostinfo | sed -n 's/^[ 	]*NeXT Mach \([^:]*\):.*$/\1/p'`"
    arch="`hostinfo | sed -n 's/^Processor type: \(.*\) (.*)$/\1/p' | tr /: ..`"
    syst=""
    chip="`hostinfo | sed -n 's/^Processor type: .* (\(.*\))$/\1/p' | tr ' /:' '...'`"
    kern=""
    ;;
  *)
    oper="unknown"
    arch=""
    syst=""
    chip=""
    kern=""
    ;;
  esac
  rm -f trycpp.o trycpp
fi

case "$chip" in
80486)
  # let's try to be consistent here. (BSD/OS)
  chip=i486
  ;;
i486DX)
  # respect the hyphen hierarchy. (FreeBSD)
  chip=i486-dx
  ;;
i486.DX2)
  # respect the hyphen hierarchy. (FreeBSD)
  chip=i486-dx2
  ;;
Intel.586)
  # no, you nitwits, there is no such chip. (NeXTStep)
  chip=pentium
  ;;
i586)
  # no, you nitwits, there is no such chip. (Linux)
  chip=pentium
  ;;
i686)
  # STOP SAYING THAT! (Linux)
  chip=ppro
esac

if gcc -c x86cpuid.c
then
  if gcc -o x86cpuid x86cpuid.o
  then
    x86cpuid="`./x86cpuid | tr /: ..`"
    case "$x86cpuid" in
      ?*)
        chip="$x86cpuid"
        ;;
    esac
  fi
fi
rm -f x86cpuid x86cpuid.o

echo "$oper-:$arch-:$syst-:$chip-:$kern-" | tr ' [A-Z]' '.[a-z]'
