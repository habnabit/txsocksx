# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

import socket
import struct

from parsley import makeProtocol, stack
from twisted.internet import protocol, defer, interfaces
from twisted.python import failure
from zope.interface import implements

import txsocksx.constants as c, txsocksx.errors as e
from txsocksx import grammar

def socks_host(host):
    return chr(c.ATYP_DOMAINNAME) + chr(len(host)) + host

class _SOCKSClientTransport(object):
    def __init__(self, wrappedClient):
        self.wrappedClient = wrappedClient
        self.transport = self.wrappedClient.transport

    def __getattr__(self, attr):
        return getattr(self.transport, attr)

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


class SOCKS5Receiver(object):
    implements(interfaces.ITransport)
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

    def proxyEstablished(self, other):
        self.otherProtocol = other
        other.makeConnection(_SOCKSClientTransport(self.sender))

    def dataReceived(self, data):
        self.otherProtocol.dataReceived(data)

    def finishParsing(self, reason):
        if self.otherProtocol:
            self.otherProtocol.connectionLost(reason)
        else:
            self.factory.proxyConnectionFailed(reason)

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


class SOCKS5ClientEndpoint(object):
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, host, port, proxyEndpoint, methods={'anonymous': ()}):
        self.host = host
        self.port = port
        self.proxyEndpoint = proxyEndpoint
        self.methods = methods

    def connect(self, fac):
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


class SOCKS4AuthDispatcher(object):
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


class SOCKS4Receiver(object):
    implements(interfaces.ITransport)
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

    def proxyEstablished(self, other):
        self.otherProtocol = other
        other.makeConnection(_SOCKSClientTransport(self.sender))

    def dataReceived(self, data):
        self.otherProtocol.dataReceived(data)

    def finishParsing(self, reason):
        if self.otherProtocol:
            self.otherProtocol.connectionLost(reason)
        else:
            self.factory.proxyConnectionFailed(reason)

SOCKS4Client = makeProtocol(
    grammar.grammarSource,
    SOCKS4Sender,
    stack(SOCKS4AuthDispatcher, SOCKS4Receiver),
    grammar.bindings)

class SOCKS4ClientFactory(_SOCKSClientFactory):
    protocol = SOCKS4Client

    def __init__(self, host, port, proxiedFactory, user=''):
        self.host = host
        self.port = port
        self.user = user
        self.proxiedFactory = proxiedFactory
        self.deferred = defer.Deferred(self._cancel)

class SOCKS4ClientEndpoint(object):
    implements(interfaces.IStreamClientEndpoint)

    def __init__(self, host, port, proxyEndpoint, user=''):
        self.host = host
        self.port = port
        self.proxyEndpoint = proxyEndpoint
        self.user = user

    def connect(self, fac):
        proxyFac = SOCKS4ClientFactory(self.host, self.port, fac, self.user)
        d = self.proxyEndpoint.connect(proxyFac)
        d.addCallback(lambda proto: proxyFac.deferred)
        return d
