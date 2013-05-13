import struct

from parsley import makeProtocol
from twisted.internet import protocol, defer, interfaces
from twisted.python import failure
from zope.interface import implements

import txsocksx.constants as c, txsocksx.errors as e
from txsocksx import grammar

def socks_host(host):
    return chr(c.ATYP_DOMAINNAME) + chr(len(host)) + host

class SOCKS5ClientTransport(object):
    def __init__(self, wrappedClient):
        self.wrappedClient = wrappedClient
        self.transport = self.wrappedClient.transport

    def __getattr__(self, attr):
        return getattr(self.transport, attr)

class SOCKS5Sender(object):
    def __init__(self, transport):
        self.transport = transport

    def sendAuthMethods(self, methods):
        self.transport.write(
            struct.pack('!BB', c.VER_SOCKS5, len(methods)) + ''.join(methods))

    def sendLogin(self, username, password):
        self.transport.write(
            '\x01'
            + chr(len(username)) + username
            + chr(len(password)) + password)

    def sendRequest(self, command, host, port):
        data = struct.pack('!BBB', c.VER_SOCKS5, command, c.RSV)
        port = struct.pack('!H', port)
        self.transport.write(data + socks_host(host) + port)


class SOCKS5State(object):
    implements(interfaces.ITransport)
    otherProtocol = None

    def __init__(self, sender, parser):
        self.sender = sender
        self.factory = parser.factory
        parser.setNextRule('SOCKS5ClientState_initial')

    def connectionMade(self):
        methods = self.methods = []
        if self.factory.anonymousAuth:
            methods.append(c.AUTH_ANONYMOUS)
        if self.factory.loginAuth:
            methods.append(c.AUTH_LOGIN)
        self.sender.sendAuthMethods(methods)

    def authSelected(self, method):
        if method not in self.methods:
            raise e.MethodsNotAcceptedError('no method proprosed was accepted',
                                            self.methods, method)
        if method == c.AUTH_ANONYMOUS:
            return self._sendRequest()
        elif method == c.AUTH_LOGIN:
            self.sender.sendLogin(*self.factory.loginAuth)
            return 'SOCKS5ClientState_readLoginResponse'

    def loginResponse(self, success):
        if not success:
            raise e.LoginAuthenticationFailed(
                'username/password combination was rejected')
        return self._sendRequest()

    def _sendRequest(self):
        self.sender.sendRequest(
            c.CMD_CONNECT, self.factory.host, self.factory.port)
        return 'SOCKS5ClientState_readResponse'

    def serverResponse(self, status, address, port):
        if status != c.SOCKS5_GRANTED:
            raise e.ConnectionError('connection rejected by SOCKS server',
                                    status,
                                    e.socks5ErrorMap.get(status, status))
        self.factory.proxyConnectionEstablished(self)
        return 'SOCKSState_readData'

    def proxyEstablished(self, other):
        self.otherProtocol = other
        other.makeConnection(SOCKS5ClientTransport(self.sender))

    def dataReceived(self, data):
        self.otherProtocol.dataReceived(data)

    def connectionLost(self, reason):
        if self.otherProtocol:
            self.otherProtocol.connectionLost(reason)
        else:
            self.factory.proxyConnectionFailed(reason)

SOCKS5Client = makeProtocol(
    grammar.grammarSource, SOCKS5Sender, SOCKS5State, grammar.bindings)

class SOCKS5ClientFactory(protocol.ClientFactory):
    protocol = SOCKS5Client

    def __init__(self, host, port, proxiedFactory, anonymousAuth, loginAuth):
        if not (anonymousAuth or loginAuth):
            raise ValueError('neither anonymous nor login auth was specified')
        self.host = host
        self.port = port
        self.proxiedFactory = proxiedFactory
        self.anonymousAuth = anonymousAuth
        self.loginAuth = loginAuth
        self.deferred = defer.Deferred()

    def proxyConnectionFailed(self, reason):
        self.deferred.errback(reason)

    def clientConnectionFailed(self, connector, reason):
        self.proxyConnectionFailed(reason)

    def proxyConnectionEstablished(self, proxyProtocol):
        proto = self.proxiedFactory.buildProtocol(
            proxyProtocol.sender.transport.getPeer())
        # XXX: handle the case of `proto is None`
        proxyProtocol.proxyEstablished(proto)
        self.deferred.callback(proto)

class SOCKS5ClientEndpoint(object):
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, host, port, proxyEndpoint, anonymousAuth=True,
                 loginAuth=None):
        self.host = host
        self.port = port
        self.proxyEndpoint = proxyEndpoint
        self.anonymousAuth = anonymousAuth
        self.loginAuth = loginAuth

    def connect(self, fac):
        proxyFac = SOCKS5ClientFactory(
            self.host, self.port, fac, self.anonymousAuth, self.loginAuth)
        self.proxyEndpoint.connect(proxyFac)
        # XXX: maybe use the deferred returned here? need to more different
        # ways/times a connection can fail before connectionMade is called.
        return proxyFac.deferred
