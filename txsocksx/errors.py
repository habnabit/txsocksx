# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

import txsocksx.constants as c

class SOCKSError(Exception):
    pass

class ConnectionLostEarly(SOCKSError):
    """
    XXX this is actually no longer being used, but is needed for backward
    compatibility.
    One day this will be removed.
    """
    pass

class MethodsNotAcceptedError(SOCKSError):
    pass

class ConnectionError(SOCKSError):
    pass

class LoginAuthenticationFailed(SOCKSError):
    pass

class ParsingError(Exception):
    pass

class InvalidServerVersion(Exception):
    pass

class InvalidServerReply(Exception):
    pass

class SOCKSError(Exception):
    pass

class StateError(Exception):
    """
    There was a problem with the State.
    """
    pass

class NoAcceptableMethods(SOCKSError):
    """
    No Acceptable Methods ( FF )
    """

class ServerFailure(SOCKSError):
    """
    General SOCKS server failure ( 1 )
    """

class ConnectionNotAllowed(SOCKSError):
    """
    Connection not allowed ( 2 )
    """

class NetworkUnreachable(SOCKSError):
    """
    Network unreachable ( 3 )
    """

class HostUnreachable(SOCKSError):
    """
    Host unreachable ( 4 )
    """

class ConnectionRefused(SOCKSError):
    """
    Connection refused ( 5 )
    """

class TTLExpired(SOCKSError):
    """
    TTL expired ( 6 )
    """

class CommandNotSupported(SOCKSError):
    """
    Command Not Supported ( 7 )
    """

class AddressNotSupported(SOCKSError):
    """
    Address type not supported ( 8 )
    """

socks5ErrorMap = {
    c.SOCKS5_GENERAL_FAILURE: ServerFailure,
    c.SOCKS5_REJECTED: ConnectionNotAllowed,
    c.SOCKS5_NETWORK_UNREACHABLE: NetworkUnreachable,
    c.SOCKS5_HOST_UNREACHABLE: HostUnreachable,
    c.SOCKS5_CONNECTION_REFUSED: ConnectionRefused,
    c.SOCKS5_TTL_EXPIRED: TTLExpired,
    c.SOCKS5_COMMAND_NOT_SUPPORTED: CommandNotSupported,
    c.SOCKS5_ADDRESS_NOT_SUPPORTED: AddressNotSupported,
}


class RequestRejectedOrFailed(SOCKSError):
    """
    Request rejected or failed (0x5b)
    """

class IdentdUnreachable(SOCKSError):
    """
    Identd not running or unreachable (0x5c)
    """

class IdentdMismatch(SOCKSError):
    """
    Identd could not confirm the request's user ID (0x5a)
    """

socks4ErrorMap = {
    c.SOCKS4_REJECTED_OR_FAILED: RequestRejectedOrFailed,
    c.SOCKS4_IDENTD_UNREACHABLE: IdentdUnreachable,
    c.SOCKS4_IDENTD_MISMATCH: IdentdMismatch,
}
