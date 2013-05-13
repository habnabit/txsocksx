import struct

from qbuf.support.twisted import MultiBufferer, MODE_RAW
from twisted.internet import protocol, defer, interfaces
from twisted.python import failure
from zope.interface import implements

import txsocksx.constants as c, txsocksx.errors as e
from txsocksx import auth

def socks_host(host):
    return chr(c.ATYP_DOMAINNAME) + chr(len(host)) + host

class SOCKS5ClientTransport(object):
    def __init__(self, wrappedClient):
        self.wrappedClient = wrappedClient
        self.transport = self.wrappedClient.transport

    def __getattr__(self, attr):
        return getattr(self.transport, attr)

class SOCKS5Client(MultiBufferer):
    implements(interfaces.ITransport)
    otherProtocol = None

    def connectionMade(self):
        d = self.readReply()
        @d.addErrback
        def _eb(reason):
            self.factory.proxyConnectionFailed(reason)
            self.close()
        return d

    @defer.inlineCallbacks
    def readReply(self):
        methodMap = dict((m.method, m) for m in self.factory.authMethods)
        self.transport.write(
            struct.pack('!BB', c.VER_SOCKS5, len(methodMap))
            + ''.join(methodMap))
        method, = yield self.unpack('!xc')
        if method not in methodMap:
            raise e.MethodsNotAcceptedError('no method proprosed was accepted',
                                            methodMap.keys(), method)
        yield methodMap[method].negotiate(self)
        data = struct.pack('!BBB', c.VER_SOCKS5, c.CMD_CONNECT, c.RSV)
        port = struct.pack('!H', self.factory.port)
        self.transport.write(data + socks_host(self.factory.host) + port)
        status, address_type = yield self.unpack('!xBxB')
        if status != c.SOCKS5_GRANTED:
            raise e.ConnectionError('connection rejected by SOCKS server',
                                    status,
                                    e.socks5ErrorMap.get(status, status))

        # Discard the host and port data from the server.
        if address_type == c.ATYP_IPV4:
            yield self.read(4)
        elif address_type == c.ATYP_DOMAINNAME:
            host_length, = yield self.unpack('!B')
            yield self.read(host_length)
        elif address_type == c.ATYP_IPV6:
            yield self.read(16)
        yield self.read(2)

        self.setMode(MODE_RAW)
        self.factory.proxyConnectionEstablished(self)

    def proxyEstablished(self, other):
        self.otherProtocol = other
        other.makeConnection(SOCKS5ClientTransport(self))

    def rawDataReceived(self, data):
        # There really is no reason for this to get called; we shouldn't be in
        # raw mode until after SOCKS negotiation finishes.
        assert self.otherProtocol is not None
        self.otherProtocol.dataReceived(data)

    def connectionLost(self, reason):
        if self.otherProtocol:
            self.otherProtocol.connectionLost(reason)
        else:
            self.factory.proxyConnectionFailed(
                failure.Failure(e.ConnectionLostEarly()))

class SOCKS5ClientFactory(protocol.ClientFactory):
    protocol = SOCKS5Client

    def __init__(self, host, port, proxiedFactory, authMethods):
        self.host = host
        self.port = port
        self.proxiedFactory = proxiedFactory
        self.authMethods = authMethods
        self.deferred = defer.Deferred()

    def proxyConnectionFailed(self, reason):
        self.deferred.errback(reason)

    def clientConnectionFailed(self, connector, reason):
        self.proxyConnectionFailed(reason)

    def proxyConnectionEstablished(self, proxyProtocol):
        proto = self.proxiedFactory.buildProtocol(
            proxyProtocol.transport.getPeer())
        # XXX: handle the case of `proto is None`
        proxyProtocol.proxyEstablished(proto)
        self.deferred.callback(proto)

class SOCKS5ClientEndpoint(object):
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, host, port, proxyEndpoint, authMethods=(auth.Anonymous(),)):
        self.host = host
        self.port = port
        self.proxyEndpoint = proxyEndpoint
        self.authMethods = authMethods

    def connect(self, fac):
        proxyFac = SOCKS5ClientFactory(self.host, self.port, fac, self.authMethods)
        self.proxyEndpoint.connect(proxyFac)
        # XXX: maybe use the deferred returned here? need to more different
        # ways/times a connection can fail before connectionMade is called.
        return proxyFac.deferred
