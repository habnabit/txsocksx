# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from parsley import makeProtocol, stack
from twisted.internet.error import ConnectionLost, ConnectionRefusedError
from twisted.internet import defer, protocol
from twisted.python import failure, log
from twisted.trial import unittest
from twisted.test import proto_helpers

from txsocksx.test.util import FakeEndpoint
from txsocksx import client, errors, grammar
import txsocksx.constants as c


connectionLostFailure = failure.Failure(ConnectionLost())
connectionRefusedFailure = failure.Failure(ConnectionRefusedError())


class FakeSOCKS5ClientFactory(protocol.ClientFactory):
    protocol = client.SOCKS5Client

    def __init__(self, host='', port=0, methods={c.AUTH_ANONYMOUS: ()}):
        self.host = host
        self.port = port
        self.methods = methods
        self.reason = None
        self.accum = proto_helpers.AccumulatingProtocol()
        self.expectingReason = False

    def proxyConnectionFailed(self, reason):
        if self.expectingReason:
            self.reason = reason
        else:
            log.err(reason)

    def proxyConnectionEstablished(self, proxyProtocol):
        proxyProtocol.proxyEstablished(self.accum)


class FakeSOCKS4ClientFactory(protocol.ClientFactory):
    protocol = client.SOCKS4Client

    def __init__(self, host='', port=0, user=''):
        self.host = host
        self.port = port
        self.user = user
        self.reason = None
        self.accum = proto_helpers.AccumulatingProtocol()
        self.expectingReason = False

    def proxyConnectionFailed(self, reason):
        if self.expectingReason:
            self.reason = reason
        else:
            log.err(reason)

    def proxyConnectionEstablished(self, proxyProtocol):
        proxyProtocol.proxyEstablished(self.accum)


authAdditionGrammar = """

authAddition = 'addition' anything:x -> receiver.authedAddition(x)

"""


class AuthAdditionWrapper(object):
    def __init__(self, wrapped):
        self.w = wrapped

    def __getattr__(self, attr):
        return getattr(self.w, attr)

    authMethodMap = {
        c.AUTH_ANONYMOUS: 'anonymous',
        c.AUTH_LOGIN: 'login',
        'A': 'addition',
    }

    additionArgs = additionParsed = None

    def auth_addition(self, *a):
        self.additionArgs = a
        self.sender.transport.write('addition!')
        self.currentRule = 'authAddition'

    def authedAddition(self, x):
        self.additionParsed = x
        del self.currentRule
        self.w._sendRequest()



AdditionAuthSOCKS5Client = makeProtocol(
    grammar.grammarSource + authAdditionGrammar,
    client.SOCKS5Sender,
    stack(client.SOCKS5AuthDispatcher, AuthAdditionWrapper, client.SOCKS5Receiver),
    grammar.bindings)


class TestSOCKS5Client(unittest.TestCase):
    def makeProto(self, *a, **kw):
        protoClass = kw.pop('_protoClass', client.SOCKS5Client)
        fac = FakeSOCKS5ClientFactory(*a, **kw)
        fac.protocol = protoClass
        proto = fac.buildProtocol(None)
        transport = proto_helpers.StringTransport()
        transport.abortConnection = lambda: None
        proto.makeConnection(transport)
        return fac, proto

    def test_initialHandshake(self):
        fac, proto = self.makeProto()
        self.assertEqual(proto.transport.value(), '\x05\x01\x00')

        fac, proto = self.makeProto(methods={c.AUTH_ANONYMOUS: (), c.AUTH_LOGIN: ()})
        self.assertEqual(proto.transport.value(), '\x05\x02\x00\x02')

        fac, proto = self.makeProto(methods={c.AUTH_LOGIN: ()})
        self.assertEqual(proto.transport.value(), '\x05\x01\x02')

    def test_failedMethodSelection(self):
        fac, proto = self.makeProto()
        fac.expectingReason = True
        proto.dataReceived('\x05\xff')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(
            fac.reason.value, errors.MethodsNotAcceptedError)
        self.assertEqual(fac.reason.value.args[2], '\xff')

    def test_loginAuth(self):
        fac, proto = self.makeProto(methods={c.AUTH_LOGIN: ('spam', 'eggs')})
        proto.transport.clear()
        proto.dataReceived('\x05\x02')
        self.assertEqual(proto.transport.value(), '\x01\x04spam\x04eggs')

    def test_loginAuthAccepted(self):
        fac, proto = self.makeProto(methods={c.AUTH_LOGIN: ('spam', 'eggs')})
        proto.dataReceived('\x05\x02')
        proto.transport.clear()
        proto.dataReceived('\x01\x00')
        self.assert_(proto.transport.value())

    def test_loginAuthFailed(self):
        fac, proto = self.makeProto(methods={c.AUTH_LOGIN: ('spam', 'eggs')})
        fac.expectingReason = True
        proto.dataReceived('\x05\x02\x01\x01')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(
            fac.reason.value, errors.LoginAuthenticationFailed)

    def test_connectionRequest(self):
        fac, proto = self.makeProto('host', 0x47)
        proto.transport.clear()
        proto.dataReceived('\x05\x00')
        self.assertEqual(proto.transport.value(),
                         '\x05\x01\x00\x03\x04host\x00\x47')

        fac, proto = self.makeProto('longerhost', 0x9494)
        proto.transport.clear()
        proto.dataReceived('\x05\x00')
        self.assertEqual(proto.transport.value(),
                         '\x05\x01\x00\x03\x0alongerhost\x94\x94')

    def test_handshakeEatsEnoughBytes(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x04666666666666666622xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x03\x08somehost22xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x03\x0022xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_connectionRequestError(self):
        fac, proto = self.makeProto()
        fac.expectingReason = True
        proto.dataReceived('\x05\x00\x05\x01\x00\x03\x0022')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(fac.reason.value, errors.ServerFailure)

    def test_buffering(self):
        fac, proto = self.makeProto()
        for c in '\x05\x00\x05\x00\x00\x01444422xxxxx':
            proto.dataReceived(c)
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_connectionLostEarly(self):
        wholeRequest = '\x05\x00\x05\x00\x00\x01444422'
        for e in xrange(len(wholeRequest)):
            partialRequest = wholeRequest[:e]
            fac, proto = self.makeProto()
            fac.expectingReason = True
            if partialRequest:
                proto.dataReceived(partialRequest)
            proto.connectionLost(connectionLostFailure)
            self.failUnlessIsInstance(fac.reason.value, ConnectionLost)

    def test_connectionLostAfterNegotiation(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)

        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422xxxxx')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_authAddition(self):
        fac, proto = self.makeProto(
            _protoClass=AdditionAuthSOCKS5Client, methods={'A': ('x', 'y')})
        proto.transport.clear()
        proto.dataReceived('\x05A')
        self.assertEqual(proto.transport.value(), 'addition!')
        self.assertEqual(proto.receiver.additionArgs, ('x', 'y'))
        proto.dataReceived('additionz')
        self.assertEqual(proto.receiver.additionParsed, 'z')
        proto.dataReceived('\x05\x00\x00\x01444422xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_dataSentByPeer(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        proto.transport.clear()
        fac.accum.transport.write('xxxxx')
        self.assertEqual(proto.transport.value(), 'xxxxx')

    def test_protocolSwitchingWithoutAProtocolAttribute(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        self.assertFalse(hasattr(proto.transport, 'protocol'))

    def test_protocolSwitching(self):
        fac, proto = self.makeProto()
        proto.transport.protocol = None
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        self.assertEqual(proto.transport.protocol, fac.accum)


class TestSOCKS4Client(unittest.TestCase):
    def makeProto(self, *a, **kw):
        protoClass = kw.pop('_protoClass', client.SOCKS4Client)
        fac = FakeSOCKS4ClientFactory(*a, **kw)
        fac.protocol = protoClass
        proto = fac.buildProtocol(None)
        transport = proto_helpers.StringTransport()
        transport.abortConnection = lambda: None
        proto.makeConnection(transport)
        return fac, proto

    def test_initialHandshake(self):
        fac, proto = self.makeProto(host='0.0.0.0', port=0x1234)
        self.assertEqual(proto.transport.value(), '\x04\x01\x12\x34\x00\x00\x00\x00\x00')

    def test_initialHandshakeWithHostname(self):
        fac, proto = self.makeProto(host='example.com', port=0x4321)
        self.assertEqual(proto.transport.value(), '\x04\x01\x43\x21\x00\x00\x00\x01\x00example.com\x00')

    def test_initialHandshakeWithUser(self):
        fac, proto = self.makeProto(host='0.0.0.0', port=0x1234, user='spam')
        self.assertEqual(proto.transport.value(), '\x04\x01\x12\x34\x00\x00\x00\x00spam\x00')

    def test_initialHandshakeWithUserAndHostname(self):
        fac, proto = self.makeProto(host='spam.com', port=0x1234, user='spam')
        self.assertEqual(proto.transport.value(), '\x04\x01\x12\x34\x00\x00\x00\x01spam\x00spam.com\x00')

    def test_handshakeEatsEnoughBytes(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_connectionRequestError(self):
        fac, proto = self.makeProto()
        fac.expectingReason = True
        proto.dataReceived('\x00\x5b\x00\x00\x00\x00\x00\x00xxxxx')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(fac.reason.value, errors.RequestRejectedOrFailed)

    def test_buffering(self):
        fac, proto = self.makeProto()
        for c in '\x00\x5a\x00\x00\x00\x00\x00\x00xxxxx':
            proto.dataReceived(c)
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_connectionLostEarly(self):
        wholeRequest = '\x00\x5a\x00\x00\x00\x00\x00\x00'
        for e in xrange(len(wholeRequest)):
            partialRequest = wholeRequest[:e]
            fac, proto = self.makeProto()
            fac.expectingReason = True
            if partialRequest:
                proto.dataReceived(partialRequest)
            proto.connectionLost(connectionLostFailure)
            self.failUnlessIsInstance(fac.reason.value, ConnectionLost)

    def test_connectionLostAfterNegotiation(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)

    def test_connectionLostAfterNegotiationWithSomeBytes(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00xxxxx')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_dataSentByPeer(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        proto.transport.clear()
        fac.accum.transport.write('xxxxx')
        self.assertEqual(proto.transport.value(), 'xxxxx')

    def test_protocolSwitchingWithoutAProtocolAttribute(self):
        fac, proto = self.makeProto()
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        self.assertFalse(hasattr(proto.transport, 'protocol'))

    def test_protocolSwitching(self):
        fac, proto = self.makeProto()
        proto.transport.protocol = None
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        self.assertEqual(proto.transport.protocol, fac.accum)


class FakeFactory(protocol.ClientFactory):
    protocol = proto_helpers.AccumulatingProtocol

    def __init__(self, returnNoProtocol=False):
        self.returnNoProtocol = returnNoProtocol
        self.protocolConnectionMade = defer.Deferred()

    def buildProtocol(self, addr):
        if self.returnNoProtocol:
            return None
        self.proto = protocol.ClientFactory.buildProtocol(self, addr)
        return self.proto


class _TestSOCKSClientFactoryCommon(object):
    def setUp(self):
        self.aborted = []

    def makeProto(self, *a, **kw):
        fac = self.factory(*a, **kw)
        proto = fac.buildProtocol(None)
        transport = proto_helpers.StringTransport()
        transport.abortConnection = lambda: self.aborted.append(True)
        proto.makeConnection(transport)
        return fac, proto

    def test_cancellation(self):
        fac, proto = self.makeProto('', 0, None)
        fac.deferred.cancel()
        self.assert_(self.aborted)
        return self.assertFailure(fac.deferred, defer.CancelledError)

    def test_cancellationBeforeFailure(self):
        fac, proto = self.makeProto('', 0, None)
        fac.deferred.cancel()
        proto.connectionLost(connectionLostFailure)
        self.assert_(self.aborted)
        return self.assertFailure(fac.deferred, defer.CancelledError)

    def test_cancellationAfterFailure(self):
        fac, proto = self.makeProto('', 0, None)
        proto.connectionLost(connectionLostFailure)
        fac.deferred.cancel()
        self.assertFalse(self.aborted)
        return self.assertFailure(fac.deferred, ConnectionLost)

    def test_clientConnectionFailed(self):
        fac, proto = self.makeProto('', 0, None)
        fac.clientConnectionFailed(None, connectionRefusedFailure)
        return self.assertFailure(fac.deferred, ConnectionRefusedError)


class TestSOCKS5ClientFactory(_TestSOCKSClientFactoryCommon, unittest.TestCase):
    factory = client.SOCKS5ClientFactory

    def test_defaultFactory(self):
        fac, proto = self.makeProto('', 0, None)
        self.assertEqual(proto.transport.value(), '\x05\x01\x00')

    def test_anonymousAndLoginAuth(self):
        fac, proto = self.makeProto('', 0, None, methods={'anonymous': (), 'login': ()})
        self.assertEqual(proto.transport.value(), '\x05\x02\x00\x02')

    def test_justLoginAuth(self):
        fac, proto = self.makeProto('', 0, None, methods={'login': ()})
        self.assertEqual(proto.transport.value(), '\x05\x01\x02')

    def test_noAuthMethodsFails(self):
        self.assertRaises(
            ValueError, client.SOCKS5ClientFactory, None, None, None, methods={})

    def test_loginAuth(self):
        fac, proto = self.makeProto('', 0, None, methods={'login': ('spam', 'eggs')})
        proto.transport.clear()
        proto.dataReceived('\x05\x02')
        self.assertEqual(proto.transport.value(), '\x01\x04spam\x04eggs')

    def test_loginAuthAccepted(self):
        fac, proto = self.makeProto('', 0, None, methods={'login': ('spam', 'eggs')})
        proto.dataReceived('\x05\x02')
        proto.transport.clear()
        proto.dataReceived('\x01\x00')
        self.assert_(proto.transport.value())

    def test_buildingWrappedFactory(self):
        wrappedFac = FakeFactory()
        fac, proto = self.makeProto('', 0, wrappedFac)
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422xxxxx')
        self.assertEqual(wrappedFac.proto.data, 'xxxxx')

    def test_noProtocolFromWrappedFactory(self):
        wrappedFac = FakeFactory(returnNoProtocol=True)
        fac, proto = self.makeProto('', 0, wrappedFac)
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        self.assert_(self.aborted)
        return self.assertFailure(fac.deferred, defer.CancelledError)

    def test_dataSentByPeer(self):
        wrappedFac = FakeFactory()
        fac, proto = self.makeProto('', 0, wrappedFac)
        proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        proto.transport.clear()
        wrappedFac.proto.transport.write('xxxxx')
        self.assertEqual(proto.transport.value(), 'xxxxx')


class TestSOCKS4ClientFactory(_TestSOCKSClientFactoryCommon, unittest.TestCase):
    factory = client.SOCKS4ClientFactory

    def test_defaultFactory(self):
        fac, proto = self.makeProto('127.0.0.1', 0, None)
        self.assertEqual(proto.transport.value(), '\x04\x01\x00\x00\x7f\x00\x00\x01\x00')

    def test_hostname(self):
        fac, proto = self.makeProto('spam.com', 0, None)
        self.assertEqual(proto.transport.value(), '\x04\x01\x00\x00\x00\x00\x00\x01\x00spam.com\x00')

    def test_differentUser(self):
        fac, proto = self.makeProto('127.0.0.1', 0, None, 'spam')
        self.assertEqual(proto.transport.value(), '\x04\x01\x00\x00\x7f\x00\x00\x01spam\x00')

    def test_buildingWrappedFactory(self):
        wrappedFac = FakeFactory()
        fac, proto = self.makeProto('127.0.0.1', 0, wrappedFac)
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00xxxxx')
        self.assertEqual(wrappedFac.proto.data, 'xxxxx')

    def test_noProtocolFromWrappedFactory(self):
        wrappedFac = FakeFactory(returnNoProtocol=True)
        fac, proto = self.makeProto('', 0, wrappedFac)
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00xxxxx')
        self.assert_(self.aborted)
        return self.assertFailure(fac.deferred, defer.CancelledError)

    def test_dataSentByPeer(self):
        wrappedFac = FakeFactory()
        fac, proto = self.makeProto('', 0, wrappedFac)
        proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        proto.transport.clear()
        wrappedFac.proto.transport.write('xxxxx')
        self.assertEqual(proto.transport.value(), 'xxxxx')

    def test_invalidIPs(self):
        self.assertRaises(ValueError, client.SOCKS4ClientFactory, '0.0.0.1', 0, None)
        self.assertRaises(ValueError, client.SOCKS4ClientFactory, '0.0.0.255', 0, None)


class TestSOCKS5ClientEndpoint(unittest.TestCase):
    def test_clientConnectionFailed(self):
        proxy = FakeEndpoint(failure=connectionRefusedFailure)
        endpoint = client.SOCKS5ClientEndpoint('', 0, proxy)
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_defaultFactory(self):
        proxy = FakeEndpoint()
        endpoint = client.SOCKS5ClientEndpoint('', 0, proxy)
        endpoint.connect(None)
        self.assertEqual(proxy.transport.value(), '\x05\x01\x00')

    def test_anonymousAndLoginAuth(self):
        proxy = FakeEndpoint()
        endpoint = client.SOCKS5ClientEndpoint('', 0, proxy, methods={'anonymous': (), 'login': ()})
        endpoint.connect(None)
        self.assertEqual(proxy.transport.value(), '\x05\x02\x00\x02')

    def test_justLoginAuth(self):
        proxy = FakeEndpoint()
        endpoint = client.SOCKS5ClientEndpoint('', 0, proxy, methods={'login': ()})
        endpoint.connect(None)
        self.assertEqual(proxy.transport.value(), '\x05\x01\x02')

    def test_noAuthMethodsFails(self):
        self.assertRaises(
            ValueError, client.SOCKS5ClientEndpoint, None, None, None, methods={})

    def test_buildingWrappedFactory(self):
        wrappedFac = FakeFactory()
        proxy = FakeEndpoint()
        endpoint = client.SOCKS5ClientEndpoint('', 0, proxy)
        d = endpoint.connect(wrappedFac)
        proxy.proto.dataReceived('\x05\x00\x05\x00\x00\x01444422xxxxx')
        d.addCallback(self.assertEqual, wrappedFac.proto)
        self.assertEqual(wrappedFac.proto.data, 'xxxxx')
        return d

    def test_dataSentByPeer(self):
        wrappedFac = FakeFactory()
        proxy = FakeEndpoint()
        endpoint = client.SOCKS5ClientEndpoint('', 0, proxy)
        endpoint.connect(wrappedFac)
        proxy.proto.dataReceived('\x05\x00\x05\x00\x00\x01444422')
        proxy.proto.transport.clear()
        wrappedFac.proto.transport.write('xxxxx')
        self.assertEqual(proxy.proto.transport.value(), 'xxxxx')


class TestSOCKS4ClientEndpoint(unittest.TestCase):
    def test_clientConnectionFailed(self):
        proxy = FakeEndpoint(failure=connectionRefusedFailure)
        endpoint = client.SOCKS4ClientEndpoint('', 0, proxy)
        d = endpoint.connect(None)
        return self.assertFailure(d, ConnectionRefusedError)

    def test_defaultFactory(self):
        proxy = FakeEndpoint()
        endpoint = client.SOCKS4ClientEndpoint('127.0.0.1', 0, proxy)
        endpoint.connect(None)
        self.assertEqual(proxy.transport.value(), '\x04\x01\x00\x00\x7f\x00\x00\x01\x00')

    def test_hostname(self):
        proxy = FakeEndpoint()
        endpoint = client.SOCKS4ClientEndpoint('spam.com', 0, proxy)
        endpoint.connect(None)
        self.assertEqual(proxy.transport.value(), '\x04\x01\x00\x00\x00\x00\x00\x01\x00spam.com\x00')

    def test_differentUser(self):
        proxy = FakeEndpoint()
        endpoint = client.SOCKS4ClientEndpoint('127.0.0.1', 0, proxy, 'spam')
        endpoint.connect(None)
        self.assertEqual(proxy.transport.value(), '\x04\x01\x00\x00\x7f\x00\x00\x01spam\x00')

    def test_buildingWrappedFactory(self):
        wrappedFac = FakeFactory()
        proxy = FakeEndpoint()
        endpoint = client.SOCKS4ClientEndpoint('', 0, proxy)
        d = endpoint.connect(wrappedFac)
        proxy.proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00xxxxx')
        d.addCallback(self.assertEqual, wrappedFac.proto)
        self.assertEqual(wrappedFac.proto.data, 'xxxxx')
        return d

    def test_dataSentByPeer(self):
        wrappedFac = FakeFactory()
        proxy = FakeEndpoint()
        endpoint = client.SOCKS4ClientEndpoint('', 0, proxy)
        endpoint.connect(wrappedFac)
        proxy.proto.dataReceived('\x00\x5a\x00\x00\x00\x00\x00\x00')
        proxy.proto.transport.clear()
        wrappedFac.proto.transport.write('xxxxx')
        self.assertEqual(proxy.proto.transport.value(), 'xxxxx')

    def test_invalidIPs(self):
        self.assertRaises(ValueError, client.SOCKS4ClientEndpoint, '0.0.0.1', 0, None)
        self.assertRaises(ValueError, client.SOCKS4ClientEndpoint, '0.0.0.255', 0, None)
