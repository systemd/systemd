/* Public domain. */

#include <errno.h>
#include "error.h"

#define X(e,s) if (i == e) return s;

const char *error_str(int i)
{
  X(0,"no error")
  X(error_intr,"interrupted system call")
  X(error_nomem,"out of memory")
  X(error_noent,"file does not exist")
  X(error_txtbsy,"text busy")
  X(error_io,"input/output error")
  X(error_exist,"file already exists")
  X(error_timeout,"timed out")
  X(error_inprogress,"operation in progress")
  X(error_again,"temporary failure")
  X(error_wouldblock,"input/output would block")
  X(error_pipe,"broken pipe")
  X(error_perm,"permission denied")
  X(error_acces,"access denied")
  X(error_nodevice,"device not configured")
  X(error_proto,"protocol error")
  X(error_isdir,"is a directory")
  X(error_connrefused,"connection refused")
  X(error_notdir,"not a directory")
#ifdef ESRCH
  X(ESRCH,"no such process")
#endif
#ifdef E2BIG
  X(E2BIG,"argument list too long")
#endif
#ifdef ENOEXEC
  X(ENOEXEC,"exec format error")
#endif
#ifdef EBADF
  X(EBADF,"file descriptor not open")
#endif
#ifdef ECHILD
  X(ECHILD,"no child processes")
#endif
#ifdef EDEADLK
  X(EDEADLK,"operation would cause deadlock")
#endif
#ifdef EFAULT
  X(EFAULT,"bad address")
#endif
#ifdef ENOTBLK
  X(ENOTBLK,"not a block device")
#endif
#ifdef EBUSY
  X(EBUSY,"device busy")
#endif
#ifdef EXDEV
  X(EXDEV,"cross-device link")
#endif
#ifdef ENODEV
  X(ENODEV,"device does not support operation")
#endif
#ifdef EINVAL
  X(EINVAL,"invalid argument")
#endif
#ifdef ENFILE
  X(ENFILE,"system cannot open more files")
#endif
#ifdef EMFILE
  X(EMFILE,"process cannot open more files")
#endif
#ifdef ENOTTY
  X(ENOTTY,"not a tty")
#endif
#ifdef EFBIG
  X(EFBIG,"file too big")
#endif
#ifdef ENOSPC
  X(ENOSPC,"out of disk space")
#endif
#ifdef ESPIPE
  X(ESPIPE,"unseekable descriptor")
#endif
#ifdef EROFS
  X(EROFS,"read-only file system")
#endif
#ifdef EMLINK
  X(EMLINK,"too many links")
#endif
#ifdef EDOM
  X(EDOM,"input out of range")
#endif
#ifdef ERANGE
  X(ERANGE,"output out of range")
#endif
#ifdef EALREADY
  X(EALREADY,"operation already in progress")
#endif
#ifdef ENOTSOCK
  X(ENOTSOCK,"not a socket")
#endif
#ifdef EDESTADDRREQ
  X(EDESTADDRREQ,"destination address required")
#endif
#ifdef EMSGSIZE
  X(EMSGSIZE,"message too long")
#endif
#ifdef EPROTOTYPE
  X(EPROTOTYPE,"incorrect protocol type")
#endif
#ifdef ENOPROTOOPT
  X(ENOPROTOOPT,"protocol not available")
#endif
#ifdef EPROTONOSUPPORT
  X(EPROTONOSUPPORT,"protocol not supported")
#endif
#ifdef ESOCKTNOSUPPORT
  X(ESOCKTNOSUPPORT,"socket type not supported")
#endif
#ifdef EOPNOTSUPP
  X(EOPNOTSUPP,"operation not supported")
#endif
#ifdef EPFNOSUPPORT
  X(EPFNOSUPPORT,"protocol family not supported")
#endif
#ifdef EAFNOSUPPORT
  X(EAFNOSUPPORT,"address family not supported")
#endif
#ifdef EADDRINUSE
  X(EADDRINUSE,"address already used")
#endif
#ifdef EADDRNOTAVAIL
  X(EADDRNOTAVAIL,"address not available")
#endif
#ifdef ENETDOWN
  X(ENETDOWN,"network down")
#endif
#ifdef ENETUNREACH
  X(ENETUNREACH,"network unreachable")
#endif
#ifdef ENETRESET
  X(ENETRESET,"network reset")
#endif
#ifdef ECONNABORTED
  X(ECONNABORTED,"connection aborted")
#endif
#ifdef ECONNRESET
  X(ECONNRESET,"connection reset")
#endif
#ifdef ENOBUFS
  X(ENOBUFS,"out of buffer space")
#endif
#ifdef EISCONN
  X(EISCONN,"already connected")
#endif
#ifdef ENOTCONN
  X(ENOTCONN,"not connected")
#endif
#ifdef ESHUTDOWN
  X(ESHUTDOWN,"socket shut down")
#endif
#ifdef ETOOMANYREFS
  X(ETOOMANYREFS,"too many references")
#endif
#ifdef ELOOP
  X(ELOOP,"symbolic link loop")
#endif
#ifdef ENAMETOOLONG
  X(ENAMETOOLONG,"file name too long")
#endif
#ifdef EHOSTDOWN
  X(EHOSTDOWN,"host down")
#endif
#ifdef EHOSTUNREACH
  X(EHOSTUNREACH,"host unreachable")
#endif
#ifdef ENOTEMPTY
  X(ENOTEMPTY,"directory not empty")
#endif
#ifdef EPROCLIM
  X(EPROCLIM,"too many processes")
#endif
#ifdef EUSERS
  X(EUSERS,"too many users")
#endif
#ifdef EDQUOT
  X(EDQUOT,"disk quota exceeded")
#endif
#ifdef ESTALE
  X(ESTALE,"stale NFS file handle")
#endif
#ifdef EREMOTE
  X(EREMOTE,"too many levels of remote in path")
#endif
#ifdef EBADRPC
  X(EBADRPC,"RPC structure is bad")
#endif
#ifdef ERPCMISMATCH
  X(ERPCMISMATCH,"RPC version mismatch")
#endif
#ifdef EPROGUNAVAIL
  X(EPROGUNAVAIL,"RPC program unavailable")
#endif
#ifdef EPROGMISMATCH
  X(EPROGMISMATCH,"program version mismatch")
#endif
#ifdef EPROCUNAVAIL
  X(EPROCUNAVAIL,"bad procedure for program")
#endif
#ifdef ENOLCK
  X(ENOLCK,"no locks available")
#endif
#ifdef ENOSYS
  X(ENOSYS,"system call not available")
#endif
#ifdef EFTYPE
  X(EFTYPE,"bad file type")
#endif
#ifdef EAUTH
  X(EAUTH,"authentication error")
#endif
#ifdef ENEEDAUTH
  X(ENEEDAUTH,"not authenticated")
#endif
#ifdef ENOSTR
  X(ENOSTR,"not a stream device")
#endif
#ifdef ETIME
  X(ETIME,"timer expired")
#endif
#ifdef ENOSR
  X(ENOSR,"out of stream resources")
#endif
#ifdef ENOMSG
  X(ENOMSG,"no message of desired type")
#endif
#ifdef EBADMSG
  X(EBADMSG,"bad message type")
#endif
#ifdef EIDRM
  X(EIDRM,"identifier removed")
#endif
#ifdef ENONET
  X(ENONET,"machine not on network")
#endif
#ifdef ERREMOTE
  X(ERREMOTE,"object not local")
#endif
#ifdef ENOLINK
  X(ENOLINK,"link severed")
#endif
#ifdef EADV
  X(EADV,"advertise error")
#endif
#ifdef ESRMNT
  X(ESRMNT,"srmount error")
#endif
#ifdef ECOMM
  X(ECOMM,"communication error")
#endif
#ifdef EMULTIHOP
  X(EMULTIHOP,"multihop attempted")
#endif
#ifdef EREMCHG
  X(EREMCHG,"remote address changed")
#endif
  return "unknown error";
}
