# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

import socket

grammarSource = r"""

byte = anything:b -> ord(b)
short = byte:high byte:low -> (high << 8) | low
cstring = <(~'\x00' anything)*>:string '\x00' -> string

ipv4Address = <anything{4}>:packed -> socket.inet_ntop(socket.AF_INET, packed)
ipv6Address = <anything{16}>:packed -> socket.inet_ntop(socket.AF_INET6, packed)

SOCKS4Command = ( '\x01' -> 'tcp-connect'
                | '\x02' -> 'tcp-bind'
                )
SOCKS4HostUser = ipv4Address:host cstring:user -> (host, user)
SOCKS4aHostUser = ( '\x00'{3} ~'\x00' anything cstring:user cstring:host -> (host, user)
                  | SOCKS4HostUser
                  )

SOCKS4Request = '\x04' SOCKS4Command:command short:port SOCKS4aHostUser:hostuser -> (command, port) + hostuser
SOCKS4Response = '\x00' byte:status anything{6} -> status


SOCKS4ServerState_initial = SOCKS4Request:request -> state.clientRequest(*request)
SOCKS4ClientState_initial = SOCKS4Response:status -> state.serverResponse(status)


SOCKS5Command = (SOCKS4Command | '\x03' -> 'udp-associate')
SOCKS5Hostname = byte:length <anything{length}>:host -> host
SOCKS5Address = ( '\x01' ipv4Address:address -> address
                | '\x03' SOCKS5Hostname:host -> host
                | '\x04' ipv6Address:address -> address
                )

SOCKS5ServerAuthSelection = '\x05' anything
SOCKS5ServerLoginResponse = anything anything:status -> status == '\x00'
SOCKS5ServerResponse = '\x05' byte:status '\x00' SOCKS5Address:address short:port -> (status, address, port)

SOCKS5ClientGreeting = '\x05' byte:authMethodCount byte{authMethodCount}:authMethods -> authMethods or []
SOCKS5ClientRequest = '\x05' SOCKS5Command:command '\x00' SOCKS5Address:address short:port -> (command, address, port)


SOCKS5ServerState_initial = SOCKS5ClientGreeting:authMethods -> state.authRequested(authMethods)
SOCKS5ServerState_readRequest = SOCKS5ClientRequest:request -> state.clientRequest(*request)

SOCKS5ClientState_initial = SOCKS5ServerAuthSelection:selection -> state.authSelected(selection)
SOCKS5ClientState_readLoginResponse = SOCKS5ServerLoginResponse:response -> state.loginResponse(response)
SOCKS5ClientState_readResponse = SOCKS5ServerResponse:response -> state.serverResponse(*response)


SOCKSState_readData = anything:data -> state.dataReceived(data)

"""

bindings = {'socket': socket}
