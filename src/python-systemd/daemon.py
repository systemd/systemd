from ._daemon import (__version__,
                      booted,
                      notify,
                      _listen_fds,
                      _is_fifo,
                      _is_socket,
                      _is_socket_inet,
                      _is_socket_unix,
                      _is_mq,
                      LISTEN_FDS_START)
from socket import AF_UNSPEC as _AF_UNSPEC

def _convert_fileobj(fileobj):
    try:
        return fileobj.fileno()
    except AttributeError:
        return fileobj

def is_fifo(fileobj, path=None):
    fd = _convert_fileobj(fileobj)
    return _is_fifo(fd, path)

def is_socket(fileobj, family=_AF_UNSPEC, type=0, listening=-1):
    fd = _convert_fileobj(fileobj)
    return _is_socket(fd, family, type, listening)

def is_socket_inet(fileobj, family=_AF_UNSPEC, type=0, listening=-1, port=0):
    fd = _convert_fileobj(fileobj)
    return _is_socket_inet(fd, family, type, listening)

def is_socket_unix(fileobj, type=0, listening=-1, path=None):
    fd = _convert_fileobj(fileobj)
    return _is_socket_unix(fd, type, listening, path)

def is_mq(fileobj, path=None):
    fd = _convert_fileobj(fileobj)
    return _is_mq(fd, path)

def listen_fds(unset_environment=True):
    """Return a list of socket activated descriptors

    Example::

      (in primary window)
      $ systemd-activate -l 2000 python3 -c \\
          'from systemd.daemon import listen_fds; print(listen_fds())'
      (in another window)
      $ telnet localhost 2000
      (in primary window)
      ...
      Execing python3 (...)
      [3]
    """
    num = _listen_fds(unset_environment)
    return list(range(LISTEN_FDS_START, LISTEN_FDS_START + num))
