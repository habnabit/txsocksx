import txsocksx.constants as c

class SOCKSError(Exception):
    pass

class MethodsNotAcceptedError(SOCKSError):
    pass

class ConnectionError(SOCKSError):
    pass

class LoginAuthenticationFailed(SOCKSError):
    pass

socks5ErrorMap = {
    c.SOCKS5_GENERAL_FAILURE: "general SOCKS server failure",
    c.SOCKS5_REJECTED: "connection not allowed by ruleset",
    c.SOCKS5_NETWORK_UNREACHABLE: "network unreachable",
    c.SOCKS5_HOST_UNREACHABLE: "host unreachable",
    c.SOCKS5_CONNECTION_REFUSED: "connection refused",
    c.SOCKS5_TTL_EXPIRED: "TTL expired",
    c.SOCKS5_COMMAND_NOT_SUPPORTED: "command not supported",
    c.SOCKS5_ADDRESS_NOT_SUPPORTED: "address type not supported",
}
