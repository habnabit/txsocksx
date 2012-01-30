from twisted.internet.error import ConnectionLost
from twisted.internet import defer, protocol
from twisted.python import failure
from twisted.trial import unittest
from twisted.test import proto_helpers

from txsocksx import client, errors

class FakeAuthMethod(object):
    def __init__(self, method):
        self.method = method
        self.negotiated = False

    def negotiate(self, proto):
        self.negotiated = True
        return defer.succeed(None)

class AuthFailed(Exception):
    pass

class FailingAuthMethod(object):
    def __init__(self, method):
        self.method = method

    def negotiate(self, proto):
        return defer.fail(AuthFailed(self.method))

methodA = FakeAuthMethod('A')
methodB = FakeAuthMethod('B')
methodC = FailingAuthMethod('C')
methodD = FailingAuthMethod('D')

connectionLostFailure = failure.Failure(ConnectionLost())

class FakeSocks5ClientFactory(protocol.ClientFactory):
    protocol = client.Socks5Client

    def __init__(self, authMethods, host=None, port=None):
        self.host = host
        self.port = port
        self.authMethods = authMethods
        self.reason = None
        self.accum = proto_helpers.AccumulatingProtocol()

    def proxyConnectionFailed(self, reason):
        self.reason = reason

    def proxyConnectionEstablished(self, proxyProtocol):
        proxyProtocol.proxyEstablished(self.accum)

class TestSocks5Client(unittest.TestCase):
    def makeProto(self, *a, **kw):
        fac = FakeSocks5ClientFactory(*a, **kw)
        proto = fac.buildProtocol(None)
        proto.makeConnection(proto_helpers.StringTransport())
        return fac, proto

    def test_initialHandshake(self):
        fac, proto = self.makeProto([methodA])
        self.assertEqual(proto.transport.value(), '\x05\x01A')

        fac, proto = self.makeProto([methodB])
        self.assertEqual(proto.transport.value(), '\x05\x01B')

        fac, proto = self.makeProto([methodA, methodB])
        self.assertEqual(proto.transport.value(), '\x05\x02AB')

    def checkMethod(self, method):
        self.assert_(method.negotiated,
                     'method %r not negotiated' % (method.method,))
        method.negotiated = False

    def test_methodNegotiation(self):
        fac, proto = self.makeProto([methodA])
        proto.dataReceived('\x05A')
        self.checkMethod(methodA)

        fac, proto = self.makeProto([methodB])
        proto.dataReceived('\x05B')
        self.checkMethod(methodB)

        fac, proto = self.makeProto([methodA, methodB])
        proto.dataReceived('\x05A')
        self.checkMethod(methodA)

        fac, proto = self.makeProto([methodA, methodB])
        proto.dataReceived('\x05B')
        self.checkMethod(methodB)

    def test_failedMethodSelection(self):
        fac, proto = self.makeProto([methodC])
        proto.dataReceived('\x05\xff')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(
            fac.reason.value, errors.MethodsNotAcceptedError)
        self.assertEqual(fac.reason.value.args[2], '\xff')

    def checkFailedMethod(self, fac, method):
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(fac.reason.value, AuthFailed)
        self.assertEqual(fac.reason.value.args[0], method.method)

    def test_failedMethodNegotiation(self):
        fac, proto = self.makeProto([methodC])
        proto.dataReceived('\x05C')
        self.checkFailedMethod(fac, methodC)

        fac, proto = self.makeProto([methodD])
        proto.dataReceived('\x05D')
        self.checkFailedMethod(fac, methodD)

        fac, proto = self.makeProto([methodC, methodD])
        proto.dataReceived('\x05C')
        self.checkFailedMethod(fac, methodC)

        fac, proto = self.makeProto([methodC, methodD])
        proto.dataReceived('\x05D')
        self.checkFailedMethod(fac, methodD)

    def test_connectionRequest(self):
        fac, proto = self.makeProto([methodA], 'host', 0x47)
        proto.transport.clear()
        proto.dataReceived('\x05A')
        self.assertEqual(proto.transport.value(),
                         '\x05\x01\x00\x03\x04host\x00\x47')

        fac, proto = self.makeProto([methodA], 'longerhost', 0x9494)
        proto.transport.clear()
        proto.dataReceived('\x05A')
        self.assertEqual(proto.transport.value(),
                         '\x05\x01\x00\x03\x0alongerhost\x94\x94')

    def test_handshakeEatsEnoughBytes(self):
        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x00\x00\x01444422xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x00\x00\x04666666666666666622xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x00\x00\x03\x08somehost22xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x00\x00\x03\x0022xxxxx')
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_connectionRequestError(self):
        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x01\x00\x03\x0022')
        self.failIfEqual(fac.reason, None)
        self.failUnlessIsInstance(fac.reason.value, errors.ConnectionError)
        self.assertEqual(fac.reason.value.args[1], 0x01)

    def test_buffering(self):
        fac, proto = self.makeProto([methodA], '', 0)
        for c in '\x05A\x05\x00\x00\x01444422xxxxx':
            proto.dataReceived(c)
        self.assertEqual(fac.accum.data, 'xxxxx')

    def test_connectionLostEarly(self):
        wholeRequest = '\x05A\x05\x00\x00\x01444422'
        for e in xrange(len(wholeRequest)):
            partialRequest = wholeRequest[:e]
            fac, proto = self.makeProto([methodA], '', 0)
            if partialRequest:
                proto.dataReceived(partialRequest)
            proto.connectionLost(connectionLostFailure)
            self.failUnlessIsInstance(fac.reason.value, errors.ConnectionLostEarly)

    def test_connectionLost(self):
        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x00\x00\x01444422')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)

        fac, proto = self.makeProto([methodA], '', 0)
        proto.dataReceived('\x05A\x05\x00\x00\x01444422xxxxx')
        proto.connectionLost(connectionLostFailure)
        self.assertEqual(fac.accum.closedReason, connectionLostFailure)
        self.assertEqual(fac.accum.data, 'xxxxx')
