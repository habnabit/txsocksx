# Copyright (c) Aaron Gallagher <_@habnab.it>
# See COPYING for details.

from parsley import makeProtocol, stack
from twisted.internet.error import ConnectionLost
from twisted.internet import protocol
from twisted.python import failure, log
from twisted.trial import unittest
from twisted.test import proto_helpers

from txsocksx import client, errors, grammar
import txsocksx.constants as c

connectionLostFailure = failure.Failure(ConnectionLost())

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
