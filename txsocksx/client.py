# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

"""SOCKS4/4a and SOCKS5 client endpoints.

"""


import socket
import struct

from parsley import makeProtocol, stack
from twisted.internet import protocol, defer, interfaces
from zope.interface import implementer

import txsocksx.constants as c, txsocksx.errors as e
from txsocksx import grammar


def socks_host(host):
    return chr(c.ATYP_DOMAINNAME) + chr(len(host)) + host

def validateSOCKS4aHost(host):
    try:
        host = socket.inet_pton(socket.AF_INET, host)
    except socket.error:
        return
    if host[:3] == '\0\0\0' and host[3] != '\0':
        raise ValueError('SOCKS4a reserves addresses 0.0.0.1-0.0.0.255')


class _SOCKSClientFactory(protocol.ClientFactory):
    currentCandidate = None
    canceled = False

    def _cancel(self, d):
        self.currentCandidate.sender.transport.abortConnection()
        self.canceled = True

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.factory = self
        self.currentCandidate = proto
        return proto

    def proxyConnectionFailed(self, reason):
        if not self.canceled:
            self.deferred.errback(reason)

    # this method is not called if an endpoint deferred errbacks
    def clientConnectionFailed(self, connector, reason):
        self.proxyConnectionFailed(reason)

    def proxyConnectionEstablished(self, proxyProtocol):
        proto = self.proxiedFactory.buildProtocol(
            proxyProtocol.sender.transport.getPeer())
        if proto is None:
            self.deferred.cancel()
            return
        proxyProtocol.proxyEstablished(proto)
        self.deferred.callback(proto)

class _SOCKSReceiver(object):
    def proxyEstablished(self, other):
        self.otherProtocol = other
        other.makeConnection(self.sender.transport)

        # a bit rude, but a huge performance increase
        if hasattr(self.sender.transport, 'protocol'):
            self.sender.transport.protocol = other

    def dataReceived(self, data):
        self.otherProtocol.dataReceived(data)

    def finishParsing(self, reason):
        if self.otherProtocol:
            self.otherProtocol.connectionLost(reason)
        else:
            self.factory.proxyConnectionFailed(reason)


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


class SOCKS5AuthDispatcher(object):
    def __init__(self, wrapped):
        self.w = wrapped

    def __getattr__(self, attr):
        return getattr(self.w, attr)

    def authSelected(self, method):
        if method not in self.w.factory.methods:
            raise e.MethodsNotAcceptedError('no method proprosed was accepted',
                                            self.w.factory.methods, method)
        authMethod = getattr(self.w, 'auth_' + self.w.authMethodMap[method])
        authMethod(*self.w.factory.methods[method])


class SOCKS5Receiver(_SOCKSReceiver):
    otherProtocol = None
    currentRule = 'SOCKS5ClientState_initial'

    def __init__(self, sender):
        self.sender = sender

    def prepareParsing(self, parser):
        self.factory = parser.factory
        self.sender.sendAuthMethods(self.factory.methods)

    authMethodMap = {
        c.AUTH_ANONYMOUS: 'anonymous',
        c.AUTH_LOGIN: 'login',
    }

    def auth_anonymous(self):
        self._sendRequest()

    def auth_login(self, username, password):
        self.sender.sendLogin(username, password)
        self.currentRule = 'SOCKS5ClientState_readLoginResponse'

    def loginResponse(self, success):
        if not success:
            raise e.LoginAuthenticationFailed(
                'username/password combination was rejected')
        self._sendRequest()

    def _sendRequest(self):
        self.sender.sendRequest(
            c.CMD_CONNECT, self.factory.host, self.factory.port)
        self.currentRule = 'SOCKS5ClientState_readResponse'

    def serverResponse(self, status, address, port):
        if status != c.SOCKS5_GRANTED:
            raise e.socks5ErrorMap.get(status)()

        self.factory.proxyConnectionEstablished(self)
        self.currentRule = 'SOCKSState_readData'

SOCKS5Client = makeProtocol(
    grammar.grammarSource,
    SOCKS5Sender,
    stack(SOCKS5AuthDispatcher, SOCKS5Receiver),
    grammar.bindings)

class SOCKS5ClientFactory(_SOCKSClientFactory):
    protocol = SOCKS5Client

    authMethodMap = {
        'anonymous': c.AUTH_ANONYMOUS,
        'login': c.AUTH_LOGIN,
    }

    def __init__(self, host, port, proxiedFactory, methods={'anonymous': ()}):
        if not methods:
            raise ValueError('no auth methods were specified')
        self.host = host
        self.port = port
        self.proxiedFactory = proxiedFactory
        self.methods = dict(
            (self.authMethodMap[method], value)
            for method, value in methods.iteritems())
        self.deferred = defer.Deferred(self._cancel)


@implementer(interfaces.IStreamClientEndpoint)
class SOCKS5ClientEndpoint(object):
    """An endpoint which does SOCKS5 negotiation.

    :param host: The hostname to connect to through the SOCKS5 server. This
        will not be resolved by ``txsocksx`` but will be sent without
        modification to the SOCKS5 server to be resolved remotely.
    :param port: The port to connect to through the SOCKS5 server.
    :param proxyEndpoint: The endpoint of the SOCKS5 server. This must provide
        `IStreamClientEndpoint`__.
    :param methods: The authentication methods to try.

    Authentication methods are specified as a dict mapping from method names to
    tuples. By default, the only method tried is anonymous authentication, so
    the default *methods* is ``{'anonymous': ()}``.

    The ``anonymous`` auth method must map to an empty tuple if provided.

    The other method available by default is ``login``. ``login`` must map to a
    tuple of ``(username, password)``.

    __ http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IStreamClientEndpoint.html

    """

    def __init__(self, host, port, proxyEndpoint, methods={'anonymous': ()}):
        if not methods:
            raise ValueError('no auth methods were specified')
        self.host = host
        self.port = port
        self.proxyEndpoint = proxyEndpoint
        self.methods = methods

    def connect(self, fac):
        """Connect over SOCKS5.

        The provided factory will have its ``buildProtocol`` method once a
        SOCKS5 connection has been successfully negotiated. Returns a
        ``Deferred`` which will fire with the resulting ``Protocol`` when
        negotiation finishes, or errback for a variety of reasons. For example:

        1. If the ``Deferred`` returned by ``proxyEndpoint.connect`` errbacks
           (e.g. the connection to the SOCKS5 server was refused).
        2. If the SOCKS5 server gave a non-success response.
        3. If the SOCKS5 server did not reply with valid SOCKS5.
        4. If the ``Deferred`` returned from ``connect`` was cancelled.

        The returned ``Deferred`` is cancelable during negotiation: the
        connection will immediately close and the ``Deferred`` will errback
        with a ``CancelledError``. The ``Deferred`` can be canceled before
        negotiation starts only if the ``Deferred`` returned by
        ``proxyEndpoint.connect`` is cancelable.

        If the factory's ``buildProtocol`` returns ``None``, the connection
        will immediately close.

        """

        proxyFac = SOCKS5ClientFactory(self.host, self.port, fac, self.methods)
        d = self.proxyEndpoint.connect(proxyFac)
        d.addCallback(lambda proto: proxyFac.deferred)
        return d


class SOCKS4Sender(object):
    def __init__(self, transport):
        self.transport = transport

    def sendRequest(self, host, port, user):
        data = struct.pack('!BBH', c.VER_SOCKS4, c.CMD_CONNECT, port)
        try:
            host = socket.inet_pton(socket.AF_INET, host)
        except socket.error:
            host, suffix = '\0\0\0\1', host + '\0'
        else:
            suffix = ''
        self.transport.write(data + host + user + '\0' + suffix)


class SOCKS4Receiver(_SOCKSReceiver):
    otherProtocol = None
    currentRule = 'SOCKS4ClientState_initial'

    def __init__(self, sender):
        self.sender = sender

    def prepareParsing(self, parser):
        self.factory = parser.factory
        self.sender.sendRequest(self.factory.host, self.factory.port, self.factory.user)

    def serverResponse(self, status, host, port):
        if status != c.SOCKS4_GRANTED:
            raise e.socks4ErrorMap.get(status)()

        self.factory.proxyConnectionEstablished(self)
        self.currentRule = 'SOCKSState_readData'

SOCKS4Client = makeProtocol(
    grammar.grammarSource,
    SOCKS4Sender,
    SOCKS4Receiver,
    grammar.bindings)

class SOCKS4ClientFactory(_SOCKSClientFactory):
    protocol = SOCKS4Client

    def __init__(self, host, port, proxiedFactory, user=''):
        validateSOCKS4aHost(host)
        self.host = host
        self.port = port
        self.user = user
        self.proxiedFactory = proxiedFactory
        self.deferred = defer.Deferred(self._cancel)


@implementer(interfaces.IStreamClientEndpoint)
class SOCKS4ClientEndpoint(object):
    """An endpoint which does SOCKS4 or SOCKS4a negotiation.

    :param host: The hostname or IP to connect to through the SOCKS4 server. If
        this is a valid IPv4 address, it will be sent to the server as a SOCKS4
        request. Otherwise, *host* will be sent as a hostname in a SOCKS4a
        request. In the SOCKS4a case, the hostname will not be resolved by
        ``txsocksx`` but will be sent without modification to the SOCKS4 server
        to be resolved remotely.
    :param port: The port to connect to through the SOCKS4 server.
    :param proxyEndpoint: The endpoint of the SOCKS4 server. This must provide
        `IStreamClientEndpoint`__.
    :param user: The user ID to send to the SOCKS4 server.

    __ http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IStreamClientEndpoint.html

    """

    def __init__(self, host, port, proxyEndpoint, user=''):
        validateSOCKS4aHost(host)
        self.host = host
        self.port = port
        self.proxyEndpoint = proxyEndpoint
        self.user = user

    def connect(self, fac):
        """Connect over SOCKS4.

        The provided factory will have its ``buildProtocol`` method once a
        SOCKS4 connection has been successfully negotiated. Returns a
        ``Deferred`` which will fire with the resulting ``Protocol`` when
        negotiation finishes, or errback for a variety of reasons. For example:

        1. If the ``Deferred`` returned by ``proxyEndpoint.connect`` errbacks
           (e.g. the connection to the SOCKS4 server was refused).
        2. If the SOCKS4 server gave a non-success response.
        3. If the SOCKS4 server did not reply with valid SOCKS4.
        4. If the ``Deferred`` returned from ``connect`` was cancelled.

        The returned ``Deferred`` is cancelable during negotiation: the
        connection will immediately close and the ``Deferred`` will errback
        with a ``CancelledError``. The ``Deferred`` can be canceled before
        negotiation starts only if the ``Deferred`` returned by
        ``proxyEndpoint.connect`` is cancelable.

        If the factory's ``buildProtocol`` returns ``None``, the connection
        will immediately close.

        """

        proxyFac = SOCKS4ClientFactory(self.host, self.port, fac, self.user)
        d = self.proxyEndpoint.connect(proxyFac)
        d.addCallback(lambda proto: proxyFac.deferred)
        return d
